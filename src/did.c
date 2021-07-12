/*
 * Copyright (c) 2020 trinity-tech
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <limits.h>
#ifndef _MSC_VER
#include <unistd.h>
#endif
#include <time.h>
#include <inttypes.h>

#include <crystal.h>

#include <qrencode.h>
#include <png.h>
#include <ela_did.h>
#include <ela_jwt.h>

#include "auth.h"
#include "sandbird.h"
#include "msgq.h"
#include "err.h"
#include "rpc.h"
#include "did.h"
#include "db.h"

#define VC_FRAG "credential"
#define TAG_AUTH "[Feedsd.Auth]: "

extern Carrier *carrier;

char feeds_did_str[ELA_MAX_DID_LEN];
DIDURL *feeeds_auth_key_url;
UserInfo feeds_owner_info;
DIDDocument *feeds_doc;
char *feeds_storepass;
Credential *feeds_vc;

static char qrcode_path[PATH_MAX];
static DIDStore *feeds_didstore;
static DID *feeds_did;
static char nonce_str[NONCE_BYTES << 1];
static char feeds_url[1024];
static enum {
    NO_OWNER,
    OWNER_DECLED,
    DID_IMPED,
    VC_ISSED
} state;
static char *payload_buf;
static pthread_mutex_t http_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool http_is_running;
static pthread_t http_tid;

typedef struct {
    UserInfo info;
    char did_buf[ELA_MAX_DID_LEN];
} VCUserInfo;

static
void gen_feeds_url();

static inline
void state_set(int s)
{
    state = s;
    gen_feeds_url();
}

static inline
const char *state_str()
{
    static const char *str[] = {
        "no owner",
        "owner declared",
        "did imported",
        "credential issued"
    };

    return str[state];
}

bool create_id_tsx(const char *payload, const char *memo)
{
    (void)memo;

    payload_buf = strdup(payload);

    return true;
}

static
void gen_feeds_url()
{
    int rc;

    rc = sprintf(feeds_url, "%s://", state >= VC_ISSED ? "feeds" : "feeds_raw");

    if (state >= DID_IMPED)
        sprintf(feeds_url + rc, "%s/", feeds_did_str);

    carrier_get_address(carrier, feeds_url + strlen(feeds_url),
                    sizeof(feeds_url) - strlen(feeds_url));

    if (state < VC_ISSED)
        sprintf(feeds_url + strlen(feeds_url), "/%s", nonce_str);

    vlogI(TAG_AUTH "Generate feeds URL: %s", feeds_url);
}

#define INCHES_PER_METER (100.0/2.54)
static
int qrencode(const char *intext, const char *outfile)
{
    QRcode *qrcode;
    static FILE *fp; // avoid clobbering by setjmp.
    png_structp png_ptr;
    png_infop info_ptr;
    png_colorp palette = NULL;
    png_byte alpha_values[2];
    unsigned char *row, *p, *q;
    int x, y, xx, yy, bit;
    int realwidth;
    int margin = 4;
    int size = 3;
    int dpi = 72;
    unsigned char fg_color[4] = {0, 0, 0, 255};
    unsigned char bg_color[4] = {255, 255, 255, 255};

    qrcode = QRcode_encodeString(intext, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
    if (!qrcode)
        return -1;

    realwidth = (qrcode->width + margin * 2) * size;
    row = (unsigned char *)malloc((realwidth + 7) / 8);
    if (row == NULL) {
        vlogE(TAG_AUTH "OOM");
        QRcode_free(qrcode);
        return -1;
    }

    fp = fopen(outfile, "wb");
    if (fp == NULL) {
        vlogE(TAG_AUTH "Failed to create file: %s", outfile);
        free(row);
        QRcode_free(qrcode);
        return -1;
    }

    png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (png_ptr == NULL) {
        vlogE(TAG_AUTH "Failed to initialize PNG writer.");
        fclose(fp);
        free(row);
        QRcode_free(qrcode);
        return -1;
    }

    info_ptr = png_create_info_struct(png_ptr);
    if (info_ptr == NULL) {
        vlogE(TAG_AUTH "Failed to initialize PNG write.");
        png_destroy_write_struct(&png_ptr, NULL);
        fclose(fp);
        free(row);
        QRcode_free(qrcode);
        return -1;
    }

    if (setjmp(png_jmpbuf(png_ptr))) {
        vlogE(TAG_AUTH "Failed to write PNG image.");
        png_destroy_write_struct(&png_ptr, &info_ptr);
        fclose(fp);
        free(row);
        QRcode_free(qrcode);
        return -1;
    }

    palette = (png_colorp) malloc(sizeof(png_color) * 2);
    if (palette == NULL) {
        vlogE(TAG_AUTH "Failed to allocate memory.");
        png_destroy_write_struct(&png_ptr, &info_ptr);
        fclose(fp);
        free(row);
        QRcode_free(qrcode);
        return -1;
    }
    palette[0].red   = fg_color[0];
    palette[0].green = fg_color[1];
    palette[0].blue  = fg_color[2];
    palette[1].red   = bg_color[0];
    palette[1].green = bg_color[1];
    palette[1].blue  = bg_color[2];
    alpha_values[0] = fg_color[3];
    alpha_values[1] = bg_color[3];
    png_set_PLTE(png_ptr, info_ptr, palette, 2);
    png_set_tRNS(png_ptr, info_ptr, alpha_values, 2, NULL);

    png_init_io(png_ptr, fp);
    png_set_IHDR(png_ptr, info_ptr,
                 realwidth, realwidth,
                 1,
                 PNG_COLOR_TYPE_PALETTE,
                 PNG_INTERLACE_NONE,
                 PNG_COMPRESSION_TYPE_DEFAULT,
                 PNG_FILTER_TYPE_DEFAULT);
    png_set_pHYs(png_ptr, info_ptr,
                 dpi * INCHES_PER_METER,
                 dpi * INCHES_PER_METER,
                 PNG_RESOLUTION_METER);
    png_write_info(png_ptr, info_ptr);

    /* top margin */
    memset(row, 0xff, (realwidth + 7) / 8);
    for (y = 0; y < margin * size; y++) {
        png_write_row(png_ptr, row);
    }

    /* data */
    p = qrcode->data;
    for (y = 0; y < qrcode->width; y++) {
        memset(row, 0xff, (realwidth + 7) / 8);
        q = row;
        q += margin * size / 8;
        bit = 7 - (margin * size % 8);
        for (x = 0; x < qrcode->width; x++) {
            for (xx = 0; xx < size; xx++) {
                *q ^= (*p & 1) << bit;
                bit--;
                if(bit < 0) {
                    q++;
                    bit = 7;
                }
            }
            p++;
        }
        for (yy = 0; yy < size; yy++) {
            png_write_row(png_ptr, row);
        }
    }
    /* bottom margin */
    memset(row, 0xff, (realwidth + 7) / 8);
    for (y = 0; y < margin * size; y++) {
        png_write_row(png_ptr, row);
    }

    png_write_end(png_ptr, info_ptr);

    free(palette);
    png_destroy_write_struct(&png_ptr, &info_ptr);
    fclose(fp);
    free(row);
    QRcode_free(qrcode);

    return 0;
}

static
int hdl_http_req(sb_Event *ev)
{
    int status = 501;
    int rc;

    if (ev->type != SB_EV_REQUEST)
        return SB_RES_OK;

    vlogI(TAG_AUTH "Received HTTP request to path[%s]", ev->path);
    vlogI(TAG_AUTH "Return HTTP response: %s", feeds_url);

    if (strcmp(ev->path, "/qrcode") == 0) {
        rc = sb_send_header(ev->stream, "Content-Type", "text/json");
        if (rc < 0) {
            vlogE(TAG_AUTH "Sending HTTP header failed.");
            goto finally;
        }

        char buf[2496];
        memset(buf, 0, sizeof(buf));
        sprintf(buf, "{\"feedsURL\":\"%s\"}", feeds_url);
        vlogD(TAG_AUTH "feedsURL: %s, len:%d\n", buf, strlen(buf));

        rc = sb_write(ev->stream, buf, strlen(buf));
        if (rc < 0) {
            vlogE(TAG_AUTH "Sending QRcode failed");
            goto finally;
        }
        return SB_RES_OK;
    }

    rc = qrencode(feeds_url, qrcode_path);
    if (rc < 0)
        goto finally;

    rc = sb_send_header(ev->stream, "Content-Type", "image/png");
    if (rc < 0) {
        vlogE(TAG_AUTH "Sending HTTP header failed.");
        goto finally;
    }

    rc = sb_send_file(ev->stream, qrcode_path);
    if (rc < 0) {
        vlogE(TAG_AUTH "Sending HTTP body failed.");
        goto finally;
    }

    status = 200;

finally:
    sb_send_status(ev->stream, status, status == 200 ? "OK" : "Internal Server Error");

    remove(qrcode_path);

    return SB_RES_OK;
}

static
void *http_server_routine(void *arg)
{
    sb_Server *http = arg;

    bool running = true;
    do {
        sb_poll_server(http, 10);

        pthread_mutex_lock(&http_mutex);
        running = http_is_running;
        pthread_mutex_unlock(&http_mutex);
    } while (running);

    sb_close_server(http);

    return NULL;
}

static
int start_binding_svc(FeedsConfig *fc)
{
    sb_Options opts = {
        .host    = fc->http_ip,
        .port    = fc->http_port,
        .udata   = NULL,
        .handler = hdl_http_req
    };
    sb_Server *http;
    int rc;

    http = sb_new_server(&opts);
    if (!http) {
        vlogE(TAG_AUTH "Creating HTTP server instance failed: %s:%s is in use.",
              fc->http_ip, fc->http_port);
        return -1;
    }

    pthread_mutex_lock(&http_mutex);
    http_is_running = true;
    rc = pthread_create(&http_tid, NULL, http_server_routine, http);
    pthread_mutex_unlock(&http_mutex);
    if (rc) {
        vlogE(TAG_AUTH "HTTP server failed to start");
        http_is_running = false;
        sb_close_server(http);
        return -1;
    }

    vlogI(TAG_AUTH "HTTP server started.");

    // pthread_detach(tid);

    return 0;
}

static inline
void stop_binding_svc()
{
    pthread_mutex_lock(&http_mutex);
    http_is_running = false;
    pthread_mutex_unlock(&http_mutex);

    pthread_join(http_tid, NULL);
    //http_tid = 0;
}

static
void oinfo_clear()
{
    pthread_mutex_lock(&http_mutex);
    if (feeds_owner_info.did)
        free(feeds_owner_info.did);

    if (feeds_owner_info.name)
        free(feeds_owner_info.name);

    if (feeds_owner_info.email)
        free(feeds_owner_info.email);

    pthread_mutex_unlock(&http_mutex);

    memset(&feeds_owner_info, 0, sizeof(feeds_owner_info));
}

void did_deinit()
{
    stop_binding_svc();

    if (feeds_vc)
        Credential_Destroy(feeds_vc);

    if (feeds_doc)
        DIDDocument_Destroy(feeds_doc);

    if (feeds_storepass)
        free(feeds_storepass);

    if (feeds_didstore)
        DIDStore_Close(feeds_didstore);

    oinfo_clear();
}

static
int oinfo_init(const UserInfo *ui)
{
    pthread_mutex_lock(&http_mutex);
    feeds_owner_info.uid = ui->uid;
    feeds_owner_info.did = strdup(ui->did);
    feeds_owner_info.name = strdup(ui->name);
    feeds_owner_info.email = strdup(ui->email);
    pthread_mutex_unlock(&http_mutex);

    if (!feeds_owner_info.did || !feeds_owner_info.name || !feeds_owner_info.email) {
        oinfo_clear();
        return -1;
    }

    return 0;
}

int oinfo_upd(const UserInfo *ui)
{
    char *name = strdup(ui->name);
    char *email = strdup(ui->email);

    if (!name) {
        vlogE(TAG_AUTH "OOM");
        return -1;
    }

    if (!email) {
        vlogE(TAG_AUTH "OOM");
        free(name);
        return -1;
    }

    pthread_mutex_lock(&http_mutex);
    free(feeds_owner_info.name);
    free(feeds_owner_info.email);
    pthread_mutex_unlock(&http_mutex);

    feeds_owner_info.name = name;
    feeds_owner_info.email = email;

    return 0;
}

static
int load_feeds_doc(DID *did, void *context)
{
    (void)context;

    if (!did)
        return -1;

    feeds_doc = DIDStore_LoadDID(feeds_didstore, did);
    return -1;
}

DIDDocument *local_resolver(DID *did)
{
    return DID_Equals(did, feeds_did) == 1 ? DIDStore_LoadDID(feeds_didstore, feeds_did) : NULL;
}

int did_init(FeedsConfig *cfg)
{
    uint8_t nonce[NONCE_BYTES];
    DIDURL *vc_url = NULL;
    UserInfo *ui = NULL;
    int rc;

    sprintf(qrcode_path, "%s/qrcode.png", cfg->data_dir);

    crypto_random_nonce(nonce);
    crypto_nonce_to_str(nonce, nonce_str, sizeof(nonce_str));

    feeds_storepass = strdup(cfg->didstore_passwd);
    if (!feeds_storepass) {
        vlogE(TAG_AUTH "OOM.");
        goto failure;
    }

    feeds_didstore = DIDStore_Open(cfg->didstore_dir);
    if (!feeds_didstore) {
        vlogE(TAG_AUTH "Opening DID store failed: %s", DIDError_GetLastErrorMessage());
        goto failure;
    }

    rc = db_get_owner(&ui);
    if (rc < 0) {
        vlogE(TAG_AUTH "Getting owner from database failed.");
        goto failure;
    }

    if (!ui) {
        state_set(NO_OWNER);
        goto finally;
    }

    rc = oinfo_init(ui);
    if (rc < 0) {
        vlogE(TAG_AUTH "Initializing feeds owner info failed.");
        goto failure;
    }

    vlogI(TAG_AUTH "Owner declared: [%s]", feeds_owner_info.did);

    if (DIDStore_ContainsRootIdentities(feeds_didstore) != 1) {
        state_set(OWNER_DECLED);
        goto finally;
    }

    DIDStore_ListDIDs(feeds_didstore, DIDFilter_HasPrivateKey, load_feeds_doc, NULL);
    if (!feeds_doc) {
        state_set(OWNER_DECLED);
        goto finally;
    }

    feeds_did = DIDDocument_GetSubject(feeds_doc);
    DID_ToString(feeds_did, feeds_did_str, sizeof(feeds_did_str));
    feeeds_auth_key_url = DIDDocument_GetDefaultPublicKey(feeds_doc);
    DIDBackend_SetLocalResolveHandle(local_resolver);

    vlogI(TAG_AUTH "DID imported: [%s]", feeds_did_str);

    vc_url = DIDURL_NewByDid(feeds_did, VC_FRAG);
    if (!vc_url) {
        vlogE(TAG_AUTH "Getting VC URL failed: %s", DIDError_GetLastErrorMessage());
        goto failure;
    }

    feeds_vc = DIDStore_LoadCredential(feeds_didstore, feeds_did, vc_url);
    if (!feeds_vc) {
        state_set(DID_IMPED);
        goto finally;
    }

    vlogI(TAG_AUTH "Credential issued, ready to serve.");
    state_set(VC_ISSED);

    goto finally;

failure:
    rc = -1;

finally:
    if (!rc)
        rc = start_binding_svc(cfg);
    if (rc < 0)
        did_deinit();
    if (vc_url)
        DIDURL_Destroy(vc_url);
    deref(ui);

    return rc;
}

bool did_is_ready()
{
    return state == VC_ISSED;
}

const char *did_get_nonce()
{
    return nonce_str;
}

static
char *gen_tsx_payload()
{
    DIDBackend_SetLocalResolveHandle(NULL);
    DIDDocument_PublishDID(feeds_doc, feeeds_auth_key_url, true, feeds_storepass);
    DIDBackend_SetLocalResolveHandle(local_resolver);
    if (!payload_buf)
        vlogE(TAG_AUTH "Failed to generate transaction payload: %s", DIDError_GetLastErrorMessage());

    return payload_buf;
}

static
void clear_tsx_payload()
{
    if (payload_buf) {
        free(payload_buf);
        payload_buf = NULL;
    }
}

void hdl_decl_owner_req(Carrier *c, const char *from, Req *base)
{
    DeclOwnerReq *req = (DeclOwnerReq *)base;
    Marshalled *resp_marshal = NULL;
    UserInfo ui = {
        .uid   = OWNER_USER_ID,
        .did   = req->params.owner_did,
        .name  = "NA",
        .email = "NA"
    };

    vlogD(TAG_AUTH "Received declare_owner request from [%s]: "
          "{nonce: %s, owner_did: %s}", from, req->params.nonce, req->params.owner_did);

    if (state == NO_OWNER) {
        if (oinfo_init(&ui) < 0) {
            ErrResp resp = {
                .tsx_id = req->tsx_id,
                .ec     = ERR_INTERNAL_ERROR
            };
            resp_marshal = rpc_marshal_err_resp(&resp);
            goto finally;
        }

        if (db_upsert_user(&ui, &ui.uid) < 0) {
            oinfo_clear();
            ErrResp resp = {
                .tsx_id = req->tsx_id,
                .ec     = ERR_INTERNAL_ERROR
            };
            resp_marshal = rpc_marshal_err_resp(&resp);
            goto finally;
        }

        vlogI(TAG_AUTH "Owner declared: [%s].", req->params.owner_did);
        state_set(OWNER_DECLED);

        {
            DeclOwnerResp resp = {
                .tsx_id = req->tsx_id,
                .result = {
                    .phase       = "owner_declared",
                    .did         = NULL,
                    .tsx_payload = NULL
                }
            };
            resp_marshal = rpc_marshal_decl_owner_resp(&resp);
            vlogD(TAG_AUTH "Sending declare_owner response to [%s]: "
                  "{phase: %s, did: nil, transaction_payload: nil}", from, resp.result.phase);
        }
    } else if (strcmp(req->params.owner_did, feeds_owner_info.did)) {
        vlogE(TAG_AUTH "Owner mismatch. Expected: [%s], actual: [%s]", feeds_owner_info.did, req->params.owner_did);
        ErrResp resp = {
            .tsx_id = req->tsx_id,
            .ec     = ERR_NOT_AUTHORIZED
        };
        resp_marshal = rpc_marshal_err_resp(&resp);
    } else if (state == OWNER_DECLED) {
        DeclOwnerResp resp = {
            .tsx_id = req->tsx_id,
            .result = {
                .phase       = "owner_declared",
                .did         = NULL,
                .tsx_payload = NULL
            }
        };
        resp_marshal = rpc_marshal_decl_owner_resp(&resp);
        vlogD(TAG_AUTH "Sending declare_owner response to [%s]: "
              "{phase: %s, did: nil, transaction_payload: nil}", from, resp.result.phase);
    } else if (state == DID_IMPED) {
        DeclOwnerResp resp = {
            .tsx_id = req->tsx_id,
            .result = {
                .phase       = "did_imported",
                .did         = feeds_did_str,
                .tsx_payload = gen_tsx_payload()
            }
        };

        if (!resp.result.tsx_payload) {
            ErrResp err_resp = {
                .tsx_id = req->tsx_id,
                .ec     = ERR_INTERNAL_ERROR
            };
            resp_marshal = rpc_marshal_err_resp(&err_resp);
            goto finally;
        }

        resp_marshal = rpc_marshal_decl_owner_resp(&resp);
        vlogD(TAG_AUTH "Sending declare_owner response to [%s]: "
              "{phase: %s, did: %s, transaction_payload: %s}",
              from, resp.result.phase, resp.result.did, resp.result.tsx_payload);
        clear_tsx_payload();
    } else {
        DeclOwnerResp resp = {
            .tsx_id = req->tsx_id,
            .result = {
                .phase       = "credential_issued",
                .did         = NULL,
                .tsx_payload = NULL
            }
        };
        resp_marshal = rpc_marshal_decl_owner_resp(&resp);
        vlogD(TAG_AUTH "Sending declare_owner response to [%s]: "
              "{phase: %s, did: nil, transaction_payload: nil}", from, resp.result.phase);
    }

finally:
    if (resp_marshal) {
        msgq_enq(from, resp_marshal);
        deref(resp_marshal);
    }
}

void hdl_imp_did_req(Carrier *c, const char *from, Req *base)
{
    ImpDIDReq *req = (ImpDIDReq *)base;
    Marshalled *resp_marshal = NULL;
    RootIdentity *identity = NULL;
    char *mnemo_gen = NULL;
    int rc;

    vlogD(TAG_AUTH "Received import_did request from [%s]: "
          "{mnemonic: %s, passphrase: %s, index: %" PRIu64 "}",
          from, req->params.mnemo ? req->params.mnemo : "nil",
          req->params.passphrase ? req->params.passphrase : "nil",
          req->params.idx);

    if (state != OWNER_DECLED) {
        vlogE(TAG_AUTH "Importing DID in a wrong state. Current state: %s", state_str());
        return;
    }

    if (!req->params.mnemo) {
        mnemo_gen = (char *)Mnemonic_Generate("english");
        if (!mnemo_gen) {
            vlogE(TAG_AUTH "Generating mnemonic failed: %s", DIDError_GetLastErrorMessage());
            ErrResp resp = {
                .tsx_id = req->tsx_id,
                .ec     = ERR_INTERNAL_ERROR
            };
            resp_marshal = rpc_marshal_err_resp(&resp);
            goto finally;
        }
    }

    identity = RootIdentity_Create(req->params.mnemo ? req->params.mnemo : mnemo_gen,
            req->params.passphrase ? req->params.passphrase : "", true, feeds_didstore, feeds_storepass);
    if (!identity) {
        vlogE(TAG_AUTH "Initializing DID store rootidentity failed: %s", DIDError_GetLastErrorMessage());
        ErrResp resp = {
            .tsx_id = req->tsx_id,
            .ec     = ERR_INTERNAL_ERROR
        };
        resp_marshal = rpc_marshal_err_resp(&resp);
        goto finally;
    }

    feeds_doc = RootIdentity_NewDIDByIndex(identity, req->params.idx, feeds_storepass, NULL);
    RootIdentity_Destroy(identity);
    if (!feeds_doc) {
        vlogE(TAG_AUTH "Newing DID in DID store failed: %s", DIDError_GetLastErrorMessage());
        ErrResp resp = {
            .tsx_id = req->tsx_id,
            .ec     = ERR_INTERNAL_ERROR
        };
        resp_marshal = rpc_marshal_err_resp(&resp);
        goto finally;
    }

    feeds_did = DIDDocument_GetSubject(feeds_doc);
    DID_ToString(feeds_did, feeds_did_str, sizeof(feeds_did_str));
    feeeds_auth_key_url = DIDDocument_GetDefaultPublicKey(feeds_doc);
    DIDBackend_SetLocalResolveHandle(local_resolver);

    vlogI(TAG_AUTH "DID imported: [%s].", feeds_did_str);
    state_set(DID_IMPED);

    {
        ImpDIDResp resp = {
            .tsx_id = req->tsx_id,
            .result = {
                .did         = feeds_did_str,
                .tsx_payload = gen_tsx_payload()
            }
        };

        if (!resp.result.tsx_payload) {
            ErrResp err_resp = {
                .tsx_id = req->tsx_id,
                .ec     = ERR_INTERNAL_ERROR
            };
            resp_marshal = rpc_marshal_err_resp(&err_resp);
            goto finally;
        }

        resp_marshal = rpc_marshal_imp_did_resp(&resp);
        vlogD(TAG_AUTH "Sending import_did response to [%s]: {did: %s, transaction_payload: %s}",
              from, resp.result.did, resp.result.tsx_payload);
        clear_tsx_payload();
    }

finally:
    if (resp_marshal) {
        msgq_enq(from, resp_marshal);
        deref(resp_marshal);
    }
    if (mnemo_gen)
        Mnemonic_Free(mnemo_gen);
}

static
Marshalled *process_vc_req(const char *from, IssVCReq *req)
{
    Marshalled *resp_marshal = NULL;
    char iss_did[ELA_MAX_DID_LEN];
    DIDURL *vc_url = NULL;
    Credential *vc = NULL;

    if (state != DID_IMPED && state != VC_ISSED) {
        vlogE(TAG_AUTH "Process credential in a wrong state. Current state: %s", state_str());
        ErrResp resp = {
            .tsx_id = req->tsx_id,
            .ec     = ERR_WRONG_STATE
        };
        resp_marshal = rpc_marshal_err_resp(&resp);
        goto finally;
    }

    vc_url = DIDURL_NewByDid(feeds_did, VC_FRAG);
    if (!vc_url) {
        vlogE(TAG_AUTH "Getting VC URL failed: %s", DIDError_GetLastErrorMessage());
        ErrResp resp = {
            .tsx_id = req->tsx_id,
            .ec     = ERR_INTERNAL_ERROR
        };
        resp_marshal = rpc_marshal_err_resp(&resp);
        goto finally;
    }

    vc = Credential_FromJson(req->params.vc, feeds_did);
    if (!vc) {
        vlogE(TAG_AUTH "Unmarshalling credential failed: %s", DIDError_GetLastErrorMessage());
        ErrResp resp = {
            .tsx_id = req->tsx_id,
            .ec     = ERR_INVALID_PARAMS
        };
        resp_marshal = rpc_marshal_err_resp(&resp);
        goto finally;
    }

    if (Credential_IsValid(vc) != 1) {
        vlogE(TAG_AUTH "Credential is invalid: %s", DIDError_GetLastErrorMessage());
        ErrResp resp = {
            .tsx_id = req->tsx_id,
            .ec     = ERR_INVALID_PARAMS
        };
        resp_marshal = rpc_marshal_err_resp(&resp);
        goto finally;
    }

    if (!DIDURL_Equals(Credential_GetId(vc), vc_url)) {
        char vc_url_str[ELA_MAX_DIDURL_LEN];
        char vc_id[ELA_MAX_DIDURL_LEN];

        vlogE(TAG_AUTH "Credential ID mismatch. Expected: [%s], actual: [%s]",
              DIDURL_ToString(vc_url, vc_url_str, sizeof(vc_url_str), true),
              DIDURL_ToString(Credential_GetId(vc), vc_id, sizeof(vc_id), true));

        ErrResp resp = {
            .tsx_id = req->tsx_id,
            .ec     = ERR_INVALID_PARAMS
        };
        resp_marshal = rpc_marshal_err_resp(&resp);
        goto finally;
    }

    if (DID_Equals(Credential_GetOwner(vc), feeds_did) != 1) {
        char vc_owner_did[ELA_MAX_DID_LEN];

        vlogE(TAG_AUTH "Credential owner mismatch. Expected: [%s], actual: [%s]",
              feeds_did_str, DID_ToString(Credential_GetOwner(vc), vc_owner_did, sizeof(vc_owner_did)));

        ErrResp resp = {
            .tsx_id = req->tsx_id,
            .ec     = ERR_INVALID_PARAMS
        };
        resp_marshal = rpc_marshal_err_resp(&resp);
        goto finally;
    }

    if (strcmp(DID_ToString(Credential_GetIssuer(vc), iss_did, sizeof(iss_did)), feeds_owner_info.did)) {
        vlogE(TAG_AUTH "Credential issuer mismatch. Expected: [%s], actual: [%s]", feeds_owner_info.did, iss_did);
        ErrResp resp = {
            .tsx_id = req->tsx_id,
            .ec     = ERR_INVALID_PARAMS
        };
        resp_marshal = rpc_marshal_err_resp(&resp);
        goto finally;
    }

    if (state == VC_ISSED &&
        Credential_GetIssuanceDate(vc) <= Credential_GetIssuanceDate(feeds_vc)) {
        vlogE(TAG_AUTH "New credential issued before the current one. Current: %" PRIu64 ", new: %" PRIu64,
              (uint64_t)Credential_GetIssuanceDate(feeds_vc),
              (uint64_t)Credential_GetIssuanceDate(vc));
        ErrResp resp = {
            .tsx_id = req->tsx_id,
            .ec     = ERR_INVALID_PARAMS
        };
        resp_marshal = rpc_marshal_err_resp(&resp);
        goto finally;
    }

    if (DIDStore_StoreCredential(feeds_didstore, vc) < 0) {
        vlogE(TAG_AUTH "Storing credential failed: %s", DIDError_GetLastErrorMessage());
        ErrResp resp = {
            .tsx_id = req->tsx_id,
            .ec     = ERR_INTERNAL_ERROR
        };
        resp_marshal = rpc_marshal_err_resp(&resp);
        goto finally;
    }

    if (state == VC_ISSED)
        Credential_Destroy(feeds_vc);
    feeds_vc = vc;
    vc = NULL;

    if (state == DID_IMPED) {
        vlogI(TAG_AUTH "Credential issued, ready to serve.");
        state_set(VC_ISSED);
    } else
        vlogI(TAG_AUTH "Credential updated.");

finally:
    if (vc)
        Credential_Destroy(vc);
    if (vc_url)
        DIDURL_Destroy(vc_url);

    return resp_marshal;
}

void hdl_iss_vc_req(Carrier *c, const char *from, Req *base)
{
    IssVCReq *req = (IssVCReq *)base;
    Marshalled *resp_marshal = NULL;

    vlogD(TAG_AUTH "Received issue_credential request from [%s]: "
          "{credential: %s}", from, req->params.vc);

    resp_marshal = process_vc_req(from, req);
    if(resp_marshal)
        goto finally;

    {
        IssVCResp resp = {
            .tsx_id = req->tsx_id,
        };
        resp_marshal = rpc_marshal_iss_vc_resp(&resp);
        vlogD(TAG_AUTH "Sending issue_credential response.");
    }

finally:
    if (resp_marshal) {
        msgq_enq(from, resp_marshal);
        deref(resp_marshal);
    }
}

void hdl_update_vc_req(Carrier *c, const char *from, Req *base)
{
    UserInfo *uinfo = NULL;
    UpdateVCReq *req = (UpdateVCReq *)base;
    Marshalled *resp_marshal = NULL;

    vlogD(TAG_AUTH "Received update_credential request from [%s]: "
          "{credential: %s}", from, req->params.vc);

    if (!did_is_ready()) {
        vlogE(TAG_AUTH "Feeds DID is not ready.");
        return;
    }

    uinfo = create_uinfo_from_access_token(req->params.tk);
    if (!uinfo) {
        vlogE(TAG_AUTH "Invalid access token.");
        ErrResp resp = {
            .tsx_id = req->tsx_id,
            .ec     = ERR_ACCESS_TOKEN_EXP
        };
        resp_marshal = rpc_marshal_err_resp(&resp);
        goto finally;
    }

    if (!user_id_is_owner(uinfo->uid)) {
        vlogE(TAG_AUTH "Update credential while not being owner.");
        ErrResp resp = {
            .tsx_id = req->tsx_id,
            .ec     = ERR_NOT_AUTHORIZED
        };
        resp_marshal = rpc_marshal_err_resp(&resp);
        goto finally;
    }

    IssVCReq iss_req = {
        .method = req->method,
        .tsx_id = req->tsx_id,
        .params.vc = req->params.vc,
    };
    resp_marshal = process_vc_req(from, &iss_req);
    if(resp_marshal)
        goto finally;

    {
        UpdateVCResp resp = {
            .tsx_id = req->tsx_id,
        };
        resp_marshal = rpc_marshal_update_vc_resp(&resp);
        vlogD(TAG_AUTH "Sending update_credential response.");
    }

finally:
    if (resp_marshal) {
        msgq_enq(from, resp_marshal);
        deref(resp_marshal);
    }
}