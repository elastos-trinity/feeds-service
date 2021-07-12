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

#ifndef __DID_H__
#define __DID_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "cfg.h"
#include "obj.h"
#include "rpc.h"

extern char feeds_did_str[ELA_MAX_DID_LEN];
extern DIDURL *feeeds_auth_key_url;
extern UserInfo feeds_owner_info;
extern DIDDocument *feeds_doc;
extern char *feeds_storepass;
extern Credential *feeds_vc;

int did_init(FeedsConfig *cfg);
void did_deinit();
bool did_is_ready();
const char *did_get_nonce();
int oinfo_upd(const UserInfo *ui);
void hdl_decl_owner_req(Carrier *c, const char *from, Req *base);
void hdl_imp_did_req(Carrier *c, const char *from, Req *base);
void hdl_iss_vc_req(Carrier *c, const char *from, Req *base);
void hdl_update_vc_req(Carrier *c, const char *from, Req *base);

DIDDocument *local_resolver(DID *did);
bool create_id_tsx(const char *payload, const char *memo);

#ifdef __cplusplus
} // extern "C"
#endif

#endif //__DID_H__
