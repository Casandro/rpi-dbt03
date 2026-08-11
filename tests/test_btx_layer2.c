/*
 * Tests for software/btx_layer2.h. No framework, just enough to fail loudly.
 * Lives outside software/ because software/compile.sh compiles every *.c
 * there into its own standalone binary.
 *
 * Run with tests/run.sh.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../software/btx_layer2.h"

static int test_failures;

#define CHECK(cond)                                                          \
	do {                                                                  \
		if (!(cond)) {                                                \
			printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
			test_failures++;                                      \
		}                                                             \
	} while (0)

#define CHECK_EQ_UINT(got, want)                                             \
	do {                                                                  \
		unsigned long g_=(unsigned long)(got);                       \
		unsigned long w_=(unsigned long)(want);                      \
		if (g_!=w_) {                                                 \
			printf("  FAIL %s:%d: %s = %lu (0x%lx), want %lu (0x%lx)\n", \
			       __FILE__, __LINE__, #got, g_, g_, w_, w_);     \
			test_failures++;                                      \
		}                                                             \
	} while (0)

static void check_bytes(const char *what, const uint8_t *got, size_t gotlen,
                         const uint8_t *want, size_t wantlen)
{
	size_t i;

	if (gotlen==wantlen && memcmp(got, want, gotlen)==0)
		return;

	test_failures++;
	printf("  FAIL %s:\n    got ", what);
	for (i=0; i<gotlen; i++)
		printf("%02x ", got[i]);
	printf("\n    want ");
	for (i=0; i<wantlen; i++)
		printf("%02x ", want[i]);
	printf("\n");
}

static int test_report(const char *name)
{
	if (test_failures==0) {
		printf("ok   %s\n", name);
		return 0;
	}
	printf("FAIL %s (%d failure(s))\n", name, test_failures);
	return 1;
}

/* ------------------------------------------------------- link layer fixture */

typedef struct {
	btx_l2 link;
	uint8_t tx[8192];
	size_t tx_len;
	uint8_t keys[256];
	size_t nkeys;
	int page_sent;
	int severe;
	int tfi;
	int term_eot;
} fixture;

static void on_event(void *ctx, btx_l2_event ev, uint8_t data)
{
	fixture *f=(fixture *)ctx;

	switch (ev) {
	case BTX_L2_EV_KEY:
		if (f->nkeys<sizeof(f->keys))
			f->keys[f->nkeys++]=data;
		break;
	case BTX_L2_EV_PAGE_SENT: f->page_sent++; break;
	case BTX_L2_EV_SEVERE_ERROR: f->severe++; break;
	case BTX_L2_EV_TFI: f->tfi++; break;
	case BTX_L2_EV_TERMINAL_EOT: f->term_eot++; break;
	}
}

static void fx_init(fixture *f)
{
	memset(f, 0, sizeof(*f));
	btx_l2_init(&f->link, on_event, f);
}

/* Drain everything the exchange wants to send right now. */
static size_t pump(fixture *f)
{
	uint8_t b;
	size_t before=f->tx_len;

	while (btx_l2_tx_byte(&f->link, &b)==1) {
		if (f->tx_len<sizeof(f->tx))
			f->tx[f->tx_len++]=b;
		else
			break;
	}
	return f->tx_len-before;
}

static void rx(fixture *f, const uint8_t *bytes, size_t n)
{
	size_t i;

	for (i=0; i<n; i++)
		btx_l2_rx_byte(&f->link, bytes[i]);
}

static void rx_ack(fixture *f) { uint8_t b=BTX_L2_ACK; rx(f, &b, 1); }
static void rx_nak(fixture *f) { uint8_t b=BTX_L2_NAK; rx(f, &b, 1); }

static void rx_ack1(fixture *f)
{
	static const uint8_t s[]={ BTX_L2_DLE, BTX_L2_ACK1_2ND };
	rx(f, s, sizeof(s));
}

static void rx_ack0(fixture *f)
{
	static const uint8_t s[]={ BTX_L2_DLE, BTX_L2_ACK0_2ND };
	rx(f, s, sizeof(s));
}

static void rx_wack(fixture *f)
{
	static const uint8_t s[]={ BTX_L2_DLE, BTX_L2_WACK_2ND };
	rx(f, s, sizeof(s));
}

/* Walk a captured transmission the way a terminal would: check every Block
 * Check Character and reassemble the text. Returns -1 if malformed. */
typedef struct {
	uint8_t text[4096];
	size_t text_len;
	size_t itb_blocks;
	size_t etx_blocks;
	size_t etb_blocks;
	size_t enqs;
	size_t eots;
	size_t stxs;
} stream_info;

static int parse_stream(const uint8_t *s, size_t n, stream_info *info)
{
	size_t i=0;
	int in_text=0;
	uint16_t bcc=BTX_L2_CRC_INIT;

	memset(info, 0, sizeof(*info));

	while (i<n) {
		uint8_t c=s[i];

		if (!in_text) {
			if (c==BTX_L2_EOT) { info->eots++; i++; }
			else if (c==BTX_L2_STX) { info->stxs++; in_text=1; bcc=BTX_L2_CRC_INIT; i++; }
			else if (c==BTX_L2_ENQ) { info->enqs++; i++; }
			else return -1;
			continue;
		}

		if (c==BTX_L2_ITB || c==BTX_L2_ETB || c==BTX_L2_ETX) {
			uint16_t want;

			bcc=l2_crc16_update(bcc, c);
			if (i+2>=n) return -1;
			want=(uint16_t)(s[i+1] | ((uint16_t)s[i+2]<<8));
			if (want!=bcc) return -1;
			i+=3;

			if (c==BTX_L2_ITB) {
				info->itb_blocks++;
				bcc=BTX_L2_CRC_INIT;
			} else {
				if (c==BTX_L2_ETX) info->etx_blocks++;
				else info->etb_blocks++;
				in_text=0;
			}
			continue;
		}

		if (c==BTX_L2_ENQ) {
			info->enqs++;
			in_text=0;
			i++;
			continue;
		}

		if (info->text_len<sizeof(info->text))
			info->text[info->text_len++]=c;
		bcc=l2_crc16_update(bcc, c);
		i++;
	}
	return 0;
}

static void make_page(uint8_t *page, size_t len)
{
	size_t i;

	for (i=0; i<len; i++)
		page[i]=(uint8_t)(0x20+(i%90));
}

/* ---------------------------------------------------------------- tests */

static void test_happy_path(void)
{
	fixture f;
	uint8_t page[100];
	stream_info info;

	fx_init(&f);
	make_page(page, sizeof(page));
	CHECK_EQ_UINT(btx_l2_send_page(&f.link, page, sizeof(page)), 0);

	pump(&f);
	rx_ack(&f);
	pump(&f);
	rx_ack(&f);
	pump(&f);
	rx_ack(&f);
	pump(&f);
	rx_ack1(&f);
	pump(&f);

	CHECK_EQ_UINT(f.page_sent, 1);
	CHECK_EQ_UINT(f.severe, 0);

	CHECK_EQ_UINT(parse_stream(f.tx, f.tx_len, &info), 0);
	CHECK_EQ_UINT(info.eots, 1);
	CHECK_EQ_UINT(info.stxs, 1);
	CHECK_EQ_UINT(info.itb_blocks, 3);
	CHECK_EQ_UINT(info.etx_blocks, 1);
	CHECK_EQ_UINT(info.enqs, 0);
	check_bytes("page text", info.text, info.text_len, page, sizeof(page));
}

static void test_pipelining_gate(void)
{
	fixture f;
	uint8_t page[100];
	size_t after_first, after_ack;

	fx_init(&f);
	make_page(page, sizeof(page));
	btx_l2_send_page(&f.link, page, sizeof(page));

	after_first=pump(&f);
	CHECK_EQ_UINT(after_first, 37+32);
	CHECK_EQ_UINT(f.tx[0], BTX_L2_EOT);
	CHECK_EQ_UINT(f.tx[1], BTX_L2_STX);
	CHECK_EQ_UINT(f.tx[34], BTX_L2_ITB);

	CHECK_EQ_UINT(pump(&f), 0);

	rx_ack(&f);
	after_ack=pump(&f);
	CHECK_EQ_UINT(after_ack, 3+32);
}

static void test_first_block_responses_discarded(void)
{
	fixture f;
	uint8_t page[100];
	uint8_t b;

	fx_init(&f);
	make_page(page, sizeof(page));
	btx_l2_send_page(&f.link, page, sizeof(page));

	btx_l2_tx_byte(&f.link, &b);
	btx_l2_tx_byte(&f.link, &b);
	rx_ack(&f);

	pump(&f);
	CHECK_EQ_UINT(pump(&f), 0);
	CHECK_EQ_UINT(f.severe, 0);
}

static void test_nak_forward_abort_midmessage(void)
{
	fixture f;
	uint8_t page[100];
	size_t mark;
	stream_info info;

	fx_init(&f);
	make_page(page, sizeof(page));
	btx_l2_send_page(&f.link, page, sizeof(page));

	pump(&f);
	rx_ack(&f);
	pump(&f);

	mark=f.tx_len;
	rx_nak(&f);
	pump(&f);
	CHECK_EQ_UINT(f.tx_len-mark, 1);
	CHECK_EQ_UINT(f.tx[mark], BTX_L2_ENQ);

	mark=f.tx_len;
	rx_nak(&f);
	pump(&f);

	CHECK_EQ_UINT(f.tx[mark], BTX_L2_STX);
	CHECK_EQ_UINT(f.severe, 0);

	rx_ack(&f);
	pump(&f);
	rx_ack(&f);
	pump(&f);
	rx_ack1(&f);
	pump(&f);
	CHECK_EQ_UINT(f.page_sent, 1);

	CHECK_EQ_UINT(parse_stream(f.tx, f.tx_len, &info), 0);
	CHECK_EQ_UINT(info.enqs, 1);
	CHECK_EQ_UINT(info.stxs, 2);
	CHECK_EQ_UINT(info.etx_blocks, 1);
}

static void test_nak_on_first_block_resends_eot(void)
{
	fixture f;
	uint8_t page[100];
	size_t mark;

	fx_init(&f);
	make_page(page, sizeof(page));
	btx_l2_send_page(&f.link, page, sizeof(page));

	pump(&f);
	rx_nak(&f);
	pump(&f);
	rx_nak(&f);
	mark=f.tx_len;
	pump(&f);

	CHECK_EQ_UINT(f.tx[mark], BTX_L2_EOT);
	CHECK_EQ_UINT(f.tx[mark+1], BTX_L2_STX);
}

static void test_timeout_then_ack_nak(void)
{
	fixture f;
	uint8_t page[100];
	size_t mark;

	fx_init(&f);
	make_page(page, sizeof(page));
	btx_l2_send_page(&f.link, page, sizeof(page));

	pump(&f);
	mark=f.tx_len;
	btx_l2_tick(&f.link, BTX_L2_T_FLOWCTRL_MS);
	pump(&f);
	CHECK_EQ_UINT(f.tx[mark], BTX_L2_ENQ);

	rx_ack(&f);
	rx_nak(&f);
	mark=f.tx_len;
	pump(&f);

	CHECK_EQ_UINT(f.tx[mark], BTX_L2_STX);
	CHECK_EQ_UINT(f.severe, 0);
}

static void test_timeout_then_nak_nak(void)
{
	fixture f;
	uint8_t page[100];
	size_t mark;
	stream_info info;

	fx_init(&f);
	make_page(page, sizeof(page));
	btx_l2_send_page(&f.link, page, sizeof(page));

	pump(&f);
	rx_ack(&f);
	pump(&f);

	btx_l2_tick(&f.link, BTX_L2_T_FLOWCTRL_MS);
	mark=f.tx_len;
	pump(&f);
	CHECK_EQ_UINT(f.tx[mark], BTX_L2_ENQ);

	rx_nak(&f);
	rx_nak(&f);
	pump(&f);
	CHECK_EQ_UINT(f.severe, 0);

	rx_ack(&f);
	pump(&f);
	rx_ack(&f);
	pump(&f);
	rx_ack1(&f);
	pump(&f);
	CHECK_EQ_UINT(f.page_sent, 1);

	CHECK_EQ_UINT(parse_stream(f.tx, f.tx_len, &info), 0);
	CHECK_EQ_UINT(info.etx_blocks, 1);
}

static void test_timeout_then_ack_only_is_severe(void)
{
	fixture f;
	uint8_t page[100];
	size_t mark;

	fx_init(&f);
	make_page(page, sizeof(page));
	btx_l2_send_page(&f.link, page, sizeof(page));

	pump(&f);
	btx_l2_tick(&f.link, BTX_L2_T_FLOWCTRL_MS);
	pump(&f);

	rx_ack(&f);
	mark=f.tx_len;
	btx_l2_tick(&f.link, BTX_L2_T_RESPONSE_MS);
	pump(&f);

	CHECK_EQ_UINT(f.severe, 1);
	CHECK_EQ_UINT(f.tx[mark], BTX_L2_EOT);
}

static void test_timeout_then_nak_only_is_severe(void)
{
	fixture f;
	uint8_t page[100];

	fx_init(&f);
	make_page(page, sizeof(page));
	btx_l2_send_page(&f.link, page, sizeof(page));

	pump(&f);
	btx_l2_tick(&f.link, BTX_L2_T_FLOWCTRL_MS);
	pump(&f);

	rx_nak(&f);
	btx_l2_tick(&f.link, BTX_L2_T_RESPONSE_MS);
	pump(&f);

	CHECK_EQ_UINT(f.severe, 1);
}

static void test_final_nak_resends_last_block(void)
{
	fixture f;
	uint8_t page[100];
	size_t mark;

	fx_init(&f);
	make_page(page, sizeof(page));
	btx_l2_send_page(&f.link, page, sizeof(page));

	pump(&f);
	rx_ack(&f);
	pump(&f);
	rx_ack(&f);
	pump(&f);
	rx_ack(&f);
	pump(&f);

	mark=f.tx_len;
	rx_nak(&f);
	pump(&f);

	CHECK_EQ_UINT(f.tx[mark], BTX_L2_STX);
	CHECK_EQ_UINT(f.severe, 0);

	rx_ack1(&f);
	pump(&f);
	CHECK_EQ_UINT(f.page_sent, 1);
}

static void test_wrong_final_parity_is_severe(void)
{
	fixture f;
	uint8_t page[100];
	size_t mark;

	fx_init(&f);
	make_page(page, sizeof(page));
	btx_l2_send_page(&f.link, page, sizeof(page));

	pump(&f);
	rx_ack(&f);
	pump(&f);
	rx_ack(&f);
	pump(&f);
	rx_ack(&f);
	pump(&f);

	mark=f.tx_len;
	rx_ack0(&f);
	pump(&f);

	CHECK_EQ_UINT(f.severe, 1);
	CHECK_EQ_UINT(f.page_sent, 0);
	CHECK_EQ_UINT(f.tx[mark], BTX_L2_EOT);
}

static void test_too_many_acks_is_severe(void)
{
	fixture f;
	uint8_t page[100];

	fx_init(&f);
	make_page(page, sizeof(page));
	btx_l2_send_page(&f.link, page, sizeof(page));

	pump(&f);
	rx_ack(&f);
	rx_ack(&f);
	pump(&f);

	CHECK_EQ_UINT(f.severe, 1);
}

static void test_wack(void)
{
	fixture f;
	uint8_t page[100];
	size_t mark;

	fx_init(&f);
	make_page(page, sizeof(page));
	btx_l2_send_page(&f.link, page, sizeof(page));

	pump(&f);
	mark=f.tx_len;
	rx_wack(&f);
	pump(&f);
	CHECK_EQ_UINT(f.tx[mark], BTX_L2_ENQ);

	rx_ack(&f);
	pump(&f);
	rx_ack(&f);
	pump(&f);
	rx_ack(&f);
	pump(&f);
	rx_ack1(&f);
	pump(&f);
	CHECK_EQ_UINT(f.page_sent, 1);
	CHECK_EQ_UINT(f.severe, 0);
}

static void test_keyboard_demux(void)
{
	fixture f;
	uint8_t page[100];
	static const uint8_t keys[]={ 0x13, '4', '7', '1', '1' };
	static const uint8_t want[]={ 0x13, '4', '7', '1', '1' };

	fx_init(&f);
	make_page(page, sizeof(page));
	btx_l2_send_page(&f.link, page, sizeof(page));

	pump(&f);
	rx(&f, keys, 2);
	rx_ack(&f);
	pump(&f);
	rx(&f, keys+2, 3);
	rx_ack(&f);
	pump(&f);
	rx_ack(&f);
	pump(&f);
	rx_ack1(&f);
	pump(&f);

	CHECK_EQ_UINT(f.page_sent, 1);
	CHECK_EQ_UINT(f.severe, 0);
	check_bytes("keyboard data", f.keys, f.nkeys, want, sizeof(want));
}

static void test_terminal_eot(void)
{
	fixture f;
	uint8_t page[100];
	uint8_t eot=BTX_L2_EOT;

	fx_init(&f);
	make_page(page, sizeof(page));
	btx_l2_send_page(&f.link, page, sizeof(page));

	pump(&f);
	rx(&f, &eot, 1);

	CHECK_EQ_UINT(f.term_eot, 1);
	CHECK_EQ_UINT(btx_l2_busy(&f.link), 0);
}

static void test_tfi_negotiation(void)
{
	fixture f;
	static const uint8_t reply[]={ BTX_L2_SOH, '0', '@', '3', BTX_L2_ETX };
	uint8_t page[100];
	stream_info info;

	fx_init(&f);
	btx_l2_request_tfi(&f.link);
	pump(&f);
	CHECK_EQ_UINT(f.tx_len, 2);
	CHECK_EQ_UINT(f.tx[0], BTX_L2_SOH);
	CHECK_EQ_UINT(f.tx[1], BTX_L2_ENQ);

	rx(&f, reply, sizeof(reply));
	CHECK_EQ_UINT(f.tfi, 1);
	CHECK_EQ_UINT(f.link.itb_size, 64);
	CHECK_EQ_UINT(f.link.use_itb, 1);

	f.tx_len=0;
	make_page(page, sizeof(page));
	btx_l2_send_page(&f.link, page, sizeof(page));
	pump(&f);
	rx_ack(&f);
	pump(&f);
	rx_ack1(&f);
	pump(&f);

	CHECK_EQ_UINT(f.page_sent, 1);
	CHECK_EQ_UINT(parse_stream(f.tx, f.tx_len, &info), 0);
	CHECK_EQ_UINT(info.itb_blocks, 1);
	CHECK_EQ_UINT(info.etx_blocks, 1);
	check_bytes("64-byte blocks", info.text, info.text_len, page, sizeof(page));
}

static void test_tfi_timeout_uses_defaults(void)
{
	fixture f;

	fx_init(&f);
	btx_l2_request_tfi(&f.link);
	pump(&f);
	btx_l2_tick(&f.link, BTX_L2_T_CONTROL_MS);

	CHECK_EQ_UINT(f.tfi, 1);
	CHECK_EQ_UINT(f.link.itb_size, BTX_L2_ITB_SIZE_DEFAULT);
	CHECK_EQ_UINT(f.link.use_itb, 1);
	CHECK_EQ_UINT(btx_l2_busy(&f.link), 0);
}

static void test_tfi_no_itb_mode(void)
{
	fixture f;
	static const uint8_t reply[]={ BTX_L2_SOH, '@', '0', BTX_L2_ETX };
	uint8_t page[300];
	stream_info info;

	fx_init(&f);
	btx_l2_request_tfi(&f.link);
	pump(&f);
	rx(&f, reply, sizeof(reply));
	CHECK_EQ_UINT(f.link.use_itb, 0);
	CHECK_EQ_UINT(f.link.itb_size, 256);

	f.tx_len=0;
	make_page(page, sizeof(page));
	btx_l2_send_page(&f.link, page, sizeof(page));
	pump(&f);
	rx_ack(&f);
	pump(&f);
	rx_ack1(&f);
	pump(&f);

	CHECK_EQ_UINT(f.page_sent, 1);
	CHECK_EQ_UINT(parse_stream(f.tx, f.tx_len, &info), 0);
	CHECK_EQ_UINT(info.itb_blocks, 0);
	CHECK_EQ_UINT(info.etb_blocks, 1);
	CHECK_EQ_UINT(info.etx_blocks, 1);
	CHECK_EQ_UINT(info.stxs, 2);
	check_bytes("no-ITB blocks", info.text, info.text_len, page, sizeof(page));
}

static void test_single_block_page(void)
{
	fixture f;
	static const uint8_t page[]={ 'H', 'i' };
	stream_info info;

	fx_init(&f);
	btx_l2_send_page(&f.link, page, sizeof(page));
	pump(&f);
	rx_ack1(&f);
	pump(&f);

	CHECK_EQ_UINT(f.page_sent, 1);
	CHECK_EQ_UINT(parse_stream(f.tx, f.tx_len, &info), 0);
	CHECK_EQ_UINT(info.itb_blocks, 0);
	CHECK_EQ_UINT(info.etx_blocks, 1);
	check_bytes("short page", info.text, info.text_len, page, sizeof(page));
}

static void test_ack_parity_alternates(void)
{
	fixture f;
	static const uint8_t page[]={ 'a' };

	fx_init(&f);
	btx_l2_send_page(&f.link, page, sizeof(page));
	pump(&f);
	rx_ack1(&f);
	pump(&f);
	CHECK_EQ_UINT(f.page_sent, 1);

	btx_l2_send_page(&f.link, page, sizeof(page));
	pump(&f);
	rx_ack1(&f);
	pump(&f);
	CHECK_EQ_UINT(f.page_sent, 2);
	CHECK_EQ_UINT(f.severe, 0);
}

/* ------------------------------------------------------------ bridge tests */

#define LIMIT 256

static void test_poll_cuts_at_chunk_size(void)
{
	btx_l2_bridge g;

	btx_l2_bridge_init(&g);

	/* More than one chunk buffered: cut exactly at the chunk size, even
	 * mid-sequence - there is no other rule to honour. */
	memset(g.rx, 'A', sizeof(g.rx));
	g.rx[LIMIT]=0x1B; /* the start of an ESC sequence, split by the cut */
	g.rx_len=sizeof(g.rx);

	btx_l2_bridge_poll(&g);
	CHECK_EQ_UINT(g.inflight, LIMIT);

	btx_l2_bridge_on_event(&g, BTX_L2_EV_PAGE_SENT, 0);
	CHECK_EQ_UINT(g.rx_len, sizeof(g.rx)-LIMIT);
	CHECK_EQ_UINT(g.rx[0], 0x1B);

	/* Less than one chunk buffered: take all of it, no waiting. */
	btx_l2_init(&g.link, btx_l2_bridge_on_event, &g);
	g.rx_len=10;
	btx_l2_bridge_poll(&g);
	CHECK_EQ_UINT(g.inflight, 10);
}

static void test_aborted_message_is_sent_again(void)
{
	btx_l2_bridge g;
	uint8_t page[64];
	size_t i;

	for (i=0; i<sizeof(page); i++)
		page[i]=(uint8_t)('A'+(i%26));

	btx_l2_bridge_init(&g);
	memcpy(g.rx, page, sizeof(page));
	g.rx_len=sizeof(page);

	btx_l2_bridge_poll(&g);
	CHECK_EQ_UINT(g.inflight, sizeof(page));

	btx_l2_bridge_on_event(&g, BTX_L2_EV_TERMINAL_EOT, 0);
	CHECK_EQ_UINT(g.inflight, 0);
	CHECK_EQ_UINT(g.rx_len, sizeof(page));
	CHECK(memcmp(g.rx, page, sizeof(page))==0);
	CHECK_EQ_UINT(g.resends, 1);

	btx_l2_init(&g.link, btx_l2_bridge_on_event, &g);
	btx_l2_bridge_poll(&g);
	CHECK_EQ_UINT(g.inflight, sizeof(page));
	CHECK(memcmp(g.rx, page, sizeof(page))==0);

	btx_l2_bridge_on_event(&g, BTX_L2_EV_SEVERE_ERROR, 0);
	CHECK_EQ_UINT(g.rx_len, sizeof(page));
	CHECK_EQ_UINT(g.resends, 2);

	btx_l2_init(&g.link, btx_l2_bridge_on_event, &g);
	btx_l2_bridge_poll(&g);
	btx_l2_bridge_on_event(&g, BTX_L2_EV_PAGE_SENT, 0);
	CHECK_EQ_UINT(g.rx_len, 0);
	CHECK_EQ_UINT(g.inflight, 0);

	memcpy(g.rx, page, sizeof(page));
	g.rx_len=sizeof(page);
	g.attempts=0;
	for (i=0; i<BTX_L2_MAX_ATTEMPTS; i++) {
		btx_l2_init(&g.link, btx_l2_bridge_on_event, &g);
		btx_l2_bridge_poll(&g);
		CHECK_EQ_UINT(g.inflight, sizeof(page));
		btx_l2_bridge_on_event(&g, BTX_L2_EV_TERMINAL_EOT, 0);
	}
	CHECK_EQ_UINT(g.rx_len, 0);
	CHECK_EQ_UINT(g.lost, sizeof(page));
	CHECK_EQ_UINT(g.attempts, 0);
}

static void test_bridge_finished(void)
{
	btx_l2_bridge g;

	btx_l2_bridge_init(&g);
	CHECK_EQ_UINT(btx_l2_bridge_finished(&g), 0); /* peer still connected */

	g.peer_closed=1;
	g.linger_ms=1000;
	g.rx_len=5;
	CHECK_EQ_UINT(btx_l2_bridge_finished(&g), 0); /* still draining */

	g.rx_len=0;
	CHECK_EQ_UINT(btx_l2_bridge_finished(&g), 1); /* drained */

	g.linger_ms=1000;
	g.rx_len=100;
	btx_l2_bridge_tick(&g, 1500);
	CHECK_EQ_UINT(g.linger_ms, 0);
	CHECK_EQ_UINT(btx_l2_bridge_finished(&g), 1); /* linger expired anyway */
}

/* ---------------------------------------------------------- parity mode */

static void test_parity_roundtrip(void)
{
	int v;

	for (v=0; v<128; v++) {
		uint8_t encoded=btx_l2_parity_encode((uint8_t)v);
		int total_bits, i;

		CHECK_EQ_UINT(encoded & 0x7f, v);

		total_bits=0;
		for (i=0; i<8; i++)
			if (encoded & (1u<<i))
				total_bits++;
		CHECK_EQ_UINT(total_bits%2, 0); /* even parity */

		CHECK_EQ_UINT(btx_l2_parity_decode(encoded), v);
	}

	/* Decode never rejects, just strips bit 7, even on garbage input. */
	CHECK_EQ_UINT(btx_l2_parity_decode(0xFF), 0x7F);
}

int main(void)
{
	test_happy_path();
	test_pipelining_gate();
	test_first_block_responses_discarded();
	test_nak_forward_abort_midmessage();
	test_nak_on_first_block_resends_eot();
	test_timeout_then_ack_nak();
	test_timeout_then_nak_nak();
	test_timeout_then_ack_only_is_severe();
	test_timeout_then_nak_only_is_severe();
	test_final_nak_resends_last_block();
	test_wrong_final_parity_is_severe();
	test_too_many_acks_is_severe();
	test_wack();
	test_keyboard_demux();
	test_terminal_eot();
	test_tfi_negotiation();
	test_tfi_timeout_uses_defaults();
	test_tfi_no_itb_mode();
	test_single_block_page();
	test_ack_parity_alternates();

	test_poll_cuts_at_chunk_size();
	test_aborted_message_is_sent_again();
	test_bridge_finished();

	test_parity_roundtrip();

	return test_report("btx_layer2");
}
