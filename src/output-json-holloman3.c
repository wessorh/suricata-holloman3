/* Copyright (C) 2026 Support Intelligence, Inc.
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 */

/**
 * \file
 *
 * \author Rick Wesson <rick@support-intelligence.com>
 *
 * Holloman3 perceptual fingerprint output for HTTP bodies.
 *
 * Computes a 16-byte structural fingerprint of HTTP request and response
 * bodies and emits them as part of the EVE JSON HTTP log.  Uses libholloman3
 * for Hilbert-curve mapping + Lanczos-3 SIMD downsampling.
 *
 * Bodies smaller than 256 bytes are skipped (libholloman3 returns -3).
 * The fingerprint format is "<c>.<32 hex>" where <c> is the order character
 * derived from the buffer size.
 */

#include "suricata-common.h"
#include "conf.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "output.h"
#include "output-json.h"
#include "output-json-http.h"
#include "output-json-holloman3.h"
#include "app-layer-htp.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "util-buffer.h"

#include "holloman3.h"

typedef struct LogHolloman3FileCtx_ {
    OutputJsonCtx *eve_ctx;
} LogHolloman3FileCtx;

typedef struct JsonHolloman3LogThread_ {
    LogHolloman3FileCtx *holloman3_ctx;
} JsonHolloman3LogThread;

/* ── body fingerprinting helper ──────────────────────────────────────── */

static void holloman3_fingerprint_body(SCJsonBuilder *js,
                                        HtpBody *body, const char *key)
{
    if (body == NULL || body->sb == NULL || body->sb->region.buf == NULL)
        return;

    const uint8_t *body_data = NULL;
    uint32_t body_data_len = 0;
    uint64_t body_offset = 0;

    if (StreamingBufferGetData(body->sb, &body_data,
                                &body_data_len, &body_offset) == 0) {
        return;
    }
    if (body_data_len < 256)
        return;

    uint8_t fp[16];
    if (holloman3_fingerprint_buffer(body_data, body_data_len, fp) == 0) {
        char id[35];
        holloman3_fingerprint_string(fp, id);
        SCJbSetString(js, key, id);
    }
}

/* ── JSON logger callback ────────────────────────────────────────────── */

static void EveHolloman3LogJSON(JsonHolloman3LogThread *UNUSED(thread),
                                 SCJsonBuilder *js, htp_tx_t *tx)
{
    SCJbOpenObject(js, "holloman3");

    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud != NULL) {
        holloman3_fingerprint_body(js, &htud->request_body,
                                    "request_body");
        holloman3_fingerprint_body(js, &htud->response_body,
                                    "response_body");
    }

    SCJbClose(js);
}

static int JsonHolloman3Logger(ThreadVars *tv, void *thread_data,
                                const Packet *p, Flow *f,
                                void *alstate, void *txptr,
                                uint64_t tx_id)
{
    SCEnter();

    htp_tx_t *tx = txptr;
    JsonHolloman3LogThread *thread = (JsonHolloman3LogThread *)thread_data;

    SCJsonBuilder *js = CreateEveHeaderWithTxId(
            p, LOG_DIR_FLOW, "http", NULL, tx_id,
            thread->holloman3_ctx->eve_ctx);
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    EveHolloman3LogJSON(thread, js, tx);

    OutputJsonBuilderComplete(js);

    return TM_ECODE_OK;
}

/* ── init / deinit ───────────────────────────────────────────────────── */

static TmEcode JsonHolloman3LogThreadInit(ThreadVars *t,
        const void *initdata, void **data)
{
    JsonHolloman3LogThread *thread = SCCalloc(1,
            sizeof(JsonHolloman3LogThread));
    if (unlikely(thread == NULL))
        return TM_ECODE_FAILED;

    thread->holloman3_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;
    return TM_ECODE_OK;
}

static TmEcode JsonHolloman3LogThreadDeinit(ThreadVars *t, void *data)
{
    JsonHolloman3LogThread *thread = (JsonHolloman3LogThread *)data;
    if (thread == NULL)
        return TM_ECODE_OK;

    memset(thread, 0, sizeof(JsonHolloman3LogThread));
    SCFree(thread);
    return TM_ECODE_OK;
}

static OutputInitResult OutputHolloman3LogInitSub(SCConfNode *conf,
        OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ojc = parent_ctx->data;

    LogHolloman3FileCtx *ctx = SCCalloc(1,
            sizeof(LogHolloman3FileCtx));
    if (unlikely(ctx == NULL))
        return result;

    intmax_t order = 13;
    (void)SCConfGetChildValueInt(conf, "holloman3-curve-order", &order);

    if (holloman3_init((uint32_t)order) != 0) {
        SCLogError("holloman3_init(order=%jd) failed", order);
        SCFree(ctx);
        return result;
    }

    ctx->eve_ctx = ojc;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(ctx);
        return result;
    }
    output_ctx->data = ctx;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/* ── registration ────────────────────────────────────────────────────── */

void JsonHolloman3LogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log",
            "JsonHolloman3Log", "eve-log.http",
            OutputHolloman3LogInitSub, ALPROTO_HTTP1,
            JsonHolloman3Logger,
            JsonHolloman3LogThreadInit,
            JsonHolloman3LogThreadDeinit);
}