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

#include "err.h"

static struct {
    int err_code;
    const char *str;
} errstr[] = {
    {ERR_ALREADY_EXISTS   , "Entity Already Exists"           },
    {ERR_NOT_EXIST        , "Entity Not Exists"               },
    {ERR_NOT_AUTHORIZED   , "Operation Not Authorized"        },
    {ERR_WRONG_STATE      , "Operation In Wrong State"        },
    {ERR_ACCESS_TOKEN_EXP , "Access Token Expired"            },
    {ERR_INTERNAL_ERROR   , "Internal Error"                  },
    {ERR_INVALID_PARAMS   , "Invalid Parameters"              },
    {ERR_INVALID_CHAL_RESP, "Invalid Challenge Response"      },
    {ERR_INVALID_VC       , "Invalid Verifiable Credential"   },
    {ERR_UNKNOWN_METHOD   , "Unsupported Method"              },
    {ERR_DB_ERROR         , "Database error"                  },
    {ERR_MAX_FEEDS_LIMIT  , "Exceeded the max number of feeds"}
};

const char *err_strerror(int rc)
{
    return errstr[-rc - 1].str;
}
