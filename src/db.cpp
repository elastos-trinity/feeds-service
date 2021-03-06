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
#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#include <vector>
#include <crystal.h>
#include <sqlite3.h>

#include "did.h"
#include "ver.h"
#include "db.h"

#define TAG_DB "[Feedsd.Db  ]: "

typedef struct {
    UserInfo info;
    sqlite3_stmt *stmt;
} DBUserInfo;

typedef void *(*Row2Raw)(sqlite3_stmt *);
typedef struct DBObjIt {
    sqlite3_stmt *stmt;
    Row2Raw cb;
} DBObjIt;

typedef struct DBInitOperator {
    int item_num = 0;
    const char *table_name = NULL;
    const char *idx_param = NULL;
    const char *backup_sql = NULL;
    const char *create_sql = NULL;
    char retrive_sql[400] = {0};
    int (*p_check)(const char *, int) = NULL;
    int (*p_del_idx)(const char *) = NULL;
    int (*p_add_idx)(const char *, const char *) = NULL;
} DBInitOperator;

static sqlite3 *db;

static
int sql_execution(const char *sql)
{
    sqlite3_stmt *stmt;
    int rc;

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "Sql execution sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        vlogE(TAG_DB "Sql execute failed, [%d][%s]", __LINE__, sql);
        return -1;
    }

    return 0;
}


static
int check_table_valid(const char *table_name, int item_num)
{
    sqlite3_stmt *stmt;
    char sql[128] = {0};
    int rc;

    vlogD(TAG_DB "Ready to check table: %s", table_name);
    snprintf(sql, sizeof(sql), 
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='%s'", 
        table_name);
    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "Check table valid sqlite3_prepare_v2() failed");
        return -1;
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        vlogE(TAG_DB "Check table valid DB failed");
        sqlite3_finalize(stmt);
        return -1;
    }
    rc = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    stmt = NULL;

    if (1 == rc) {
        memset(sql, 0, sizeof(sql));
        snprintf(sql, sizeof(sql), "PRAGMA table_info('%s')", table_name);
        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "PRAGMA table_info sqlite3_prepare_v2() failed");
            return -1;
        }
        while(sqlite3_step(stmt) == SQLITE_ROW) {    //collect the column num of table
            rc = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
        if (rc + 1 == item_num) {    //check column match the expection
            vlogD(TAG_DB "Table %s is newest version", table_name);
            return 2;
        }
        return 1;
    } else if (0 == rc) {
        return 0;
    } else {
        return -1;
    }
}

static
int delete_old_index(const char *table_name)
{
    sqlite3_stmt *stmt;
    char sql[128] = {0};
    int rc;

    snprintf(sql, sizeof(sql), "DROP INDEX %s_created_at_index", table_name);
    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "Delete %s_created_at_index sqlite3_prepare_v2() failed",
            table_name);
        return -1;
    }
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        vlogE(TAG_DB "Delete %s_created_at_index failed", table_name);
        return -1;
    }

    memset(sql, 0, sizeof(sql));
    snprintf(sql, sizeof(sql), "DROP INDEX %s_updated_at_index", table_name);
    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "Delete %s_updated_at_index sqlite3_prepare_v2() failed",
            table_name);
        return -1;
    }
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        vlogE(TAG_DB "Delete %s_updated_at_index failed", table_name);
        return -1;
    }

    return 0;
}

static
int create_new_index(const char *table_name, const char *para)
{
    sqlite3_stmt *stmt;
    char sql[128] = {0};
    int rc;

    snprintf(sql, sizeof(sql), 
        "CREATE INDEX %s_created_at_index ON %s (%screated_at)", 
        table_name, table_name, para);
    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "Creating %s_created_at_index sqlite3_prepare_v2() failed", 
            table_name);
        return -1;
    }
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        vlogE(TAG_DB "Creating %s_created_at_index failed", table_name);
        return -1;
    }

    memset(sql, 0, sizeof(sql));
    snprintf(sql, sizeof(sql), 
        "CREATE INDEX %s_updated_at_index ON %s (%supdated_at)", 
        table_name, table_name, para);
    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "Creating %s_updated_at_index sqlite3_prepare_v2() failed",
            table_name);
        return -1;
    }
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        vlogE(TAG_DB "Creating %s_updated_at_index failed", table_name);
        return -1;
    }

    return 0;
}

int db_init(sqlite3 *handle)
{
    db = handle;
    std::vector<DBInitOperator *> operator_vec;

    //init tables operator
    DBInitOperator channels_op;
    channels_op.item_num = 13;
    channels_op.table_name = "channels";
    channels_op.idx_param = "";
    channels_op.backup_sql = "ALTER TABLE channels RENAME TO channels_backup";
    channels_op.create_sql = "CREATE TABLE IF NOT EXISTS channels ("
        "  channel_id    INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  created_at    REAL    NOT NULL,"
        "  updated_at    REAL    NOT NULL,"
        "  name          TEXT    NOT NULL UNIQUE,"
        "  intro         TEXT    NOT NULL,"
        "  next_post_id  INTEGER NOT NULL DEFAULT 1,"
        "  subscribers   INTEGER NOT NULL DEFAULT 0,"
        "  status        INTEGER NOT NULL DEFAULT 0,"
        "  iid           TEXT    NOT NULL,"
        "  tip_methods   TEXT    NOT NULL,"
        "  proof         TEXT    NOT NULL,"
        "  memo          TEXT    NOT NULL,"
        "  avatar        BLOB    NOT NULL"
        ")";
    strcpy(channels_op.retrive_sql,
            "INSERT INTO channels SELECT"
            " channel_id, created_at, updated_at, name, intro, next_post_id,"
            " subscribers, 0, 'NA', 'NA', 'NA', 'NA', avatar"
            " FROM channels_backup");
    channels_op.p_check = check_table_valid;
    channels_op.p_del_idx = delete_old_index;
    channels_op.p_add_idx = create_new_index;
    operator_vec.push_back(&channels_op);

    DBInitOperator posts_op;
    posts_op.item_num = 14;
    posts_op.table_name = "posts";
    posts_op.idx_param = "channel_id, ";
    posts_op.backup_sql = "ALTER TABLE posts RENAME TO posts_backup";
    posts_op.create_sql = "CREATE TABLE IF NOT EXISTS posts ("
        "  channel_id      INTEGER NOT NULL REFERENCES channels(channel_id),"
        "  post_id         INTEGER NOT NULL,"
        "  created_at      REAL    NOT NULL,"
        "  updated_at      REAL    NOT NULL,"
        "  next_comment_id INTEGER NOT NULL DEFAULT 1,"
        "  likes           INTEGER NOT NULL DEFAULT 0,"
        "  status          INTEGER NOT NULL DEFAULT 0,"
        "  iid             TEXT    NOT NULL,"
        "  hash_id         TEXT    NOT NULL,"
        "  proof           TEXT    NOT NULL,"
        "  origin_post_url TEXT    NOT NULL,"
        "  memo            TEXT    NOT NULL,"
        "  thumbnails      BLOB    NOT NULL,"
        "  content         BLOB    NOT NULL,"
        "  PRIMARY KEY(channel_id, post_id)"
        ")";
    strcpy(posts_op.retrive_sql,
            "INSERT INTO posts SELECT"
            " channel_id, post_id, created_at, updated_at, next_comment_id,"
            " likes, status, 'NA', 'NA', 'NA', 'NA', 'NA', X'A0', content"
            " FROM posts_backup");
    posts_op.p_check = check_table_valid;
    posts_op.p_del_idx = delete_old_index;
    posts_op.p_add_idx = create_new_index;
    operator_vec.push_back(&posts_op);

    DBInitOperator comments_op;
    comments_op.item_num = 15;
    comments_op.table_name = "comments";
    comments_op.idx_param = "channel_id, post_id, ";
    comments_op.backup_sql = "ALTER TABLE comments RENAME TO comments_backup";
    comments_op.create_sql = "CREATE TABLE IF NOT EXISTS comments ("
        "  channel_id    INTEGER NOT NULL,"
        "  post_id       INTEGER NOT NULL,"
        "  comment_id    INTEGER NOT NULL,"
        "  refcomment_id INTEGER NOT NULL,"
        "  user_id       INTEGER NOT NULL REFERENCES users(user_id),"
        "  created_at    REAL    NOT NULL,"
        "  updated_at    REAL    NOT NULL,"
        "  likes         INTEGER NOT NULL DEFAULT 0,"
        "  status        INTEGER NOT NULL DEFAULT 0,"
        "  iid           TEXT    NOT NULL,"
        "  hash_id       TEXT    NOT NULL,"
        "  proof         TEXT    NOT NULL,"
        "  memo          TEXT    NOT NULL,"
        "  thumbnails    BLOB    NOT NULL,"
        "  content       BLOB    NOT NULL,"
        "  PRIMARY KEY(channel_id, post_id, comment_id)"
        "  FOREIGN KEY(channel_id, post_id) REFERENCES posts(channel_id, post_id)"
        ")";
    strcpy(comments_op.retrive_sql,
            "INSERT INTO comments SELECT"
            " channel_id, post_id, comment_id, refcomment_id, user_id,"
            " created_at, updated_at, likes, status, 'NA', 'NA', 'NA', 'NA', X'A0', content"
            " FROM comments_backup");
    comments_op.p_check = check_table_valid;
    comments_op.p_del_idx = delete_old_index;
    comments_op.p_add_idx = create_new_index;
    operator_vec.push_back(&comments_op);

    DBInitOperator users_op;
    users_op.item_num = 8;
    users_op.table_name = "users";
    users_op.idx_param = NULL;
    users_op.backup_sql = "ALTER TABLE users RENAME TO users_backup";
    users_op.create_sql = "CREATE TABLE IF NOT EXISTS users ("
        "  user_id      INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  did          TEXT NOT NULL UNIQUE,"
        "  name         TEXT NOT NULL DEFAULT 'NA',"
        "  email        TEXT NOT NULL DEFAULT 'NA',"
        "  display_name TEXT NOT NULL DEFAULT 'NA',"
        "  update_at    REAL NOT NULL,"
        "  memo         TEXT NOT NULL DEFAULT 'NA',"
        "  avatar       BLOB NOT NULL DEFAULT X'A0'"
        ")";
    sprintf(users_op.retrive_sql,
            "INSERT INTO users SELECT"
            " user_id, did, name, email, 'NA', %lu, 'NA', X'A0'"
            " FROM users_backup", time(NULL));
    users_op.p_check = check_table_valid;
    users_op.p_del_idx = NULL;
    users_op.p_add_idx = NULL;
    operator_vec.push_back(&users_op);

    DBInitOperator subscriptions_op;
    subscriptions_op.item_num = 5;
    subscriptions_op.table_name = "subscriptions";
    subscriptions_op.idx_param = NULL;
    subscriptions_op.backup_sql = "ALTER TABLE subscriptions RENAME TO subscriptions_backup";
    subscriptions_op.create_sql = "CREATE TABLE IF NOT EXISTS subscriptions ("
        "  user_id    INTEGER NOT NULL REFERENCES users(user_id),"
        "  channel_id INTEGER NOT NULL REFERENCES channels(channel_id),"
        "  create_at  REAL    NOT NULL,"
        "  proof      TEXT    NOT NULL,"
        "  memo       TEXT    NOT NULL,"
        "  PRIMARY KEY(user_id, channel_id)"
        ")";
    sprintf(subscriptions_op.retrive_sql,
            "INSERT INTO subscriptions SELECT"
            " user_id, channel_id, %lu, 'NA', 'NA'"
            " FROM subscriptions_backup", time(NULL));
    subscriptions_op.p_check = check_table_valid;
    subscriptions_op.p_del_idx = NULL;
    subscriptions_op.p_add_idx = NULL;
    operator_vec.push_back(&subscriptions_op);

    DBInitOperator likes_op;
    likes_op.item_num = 7;
    likes_op.table_name = "likes";
    likes_op.idx_param = NULL;
    likes_op.backup_sql = "ALTER TABLE likes RENAME TO likes_backup";
    likes_op.create_sql = "CREATE TABLE IF NOT EXISTS likes ("
        "  channel_id INTEGER NOT NULL,"
        "  post_id    INTEGER NOT NULL,"
        "  comment_id INTEGER NOT NULL,"
        "  user_id    INTEGER NOT NULL REFERENCES users(user_id),"
        "  created_at REAL    NOT NULL,"
        "  proof      TEXT    NOT NULL,"
        "  memo       TEXT    NOT NULL,"
        "  FOREIGN KEY(channel_id, post_id) REFERENCES posts(channel_id, post_id)"
        "  PRIMARY KEY(user_id, channel_id, post_id, comment_id)"
        ")";
    strcpy(likes_op.retrive_sql,
            "INSERT INTO likes SELECT"
            " channel_id, post_id, comment_id, user_id, created_at, 'NA', 'NA'"
            " FROM likes_backup");
    likes_op.p_check = check_table_valid;
    likes_op.p_del_idx = NULL;
    likes_op.p_add_idx = NULL;
    operator_vec.push_back(&likes_op);

    DBInitOperator reported_comments_op;
    reported_comments_op.item_num = 6;
    reported_comments_op.table_name = "reported_comments";
    reported_comments_op.idx_param = NULL;
    reported_comments_op.backup_sql = NULL;
    reported_comments_op.create_sql = "CREATE TABLE IF NOT EXISTS reported_comments ("
        "  channel_id  INTEGER NOT NULL,"
        "  post_id     INTEGER NOT NULL,"
        "  comment_id  INTEGER NOT NULL,"
        "  reporter_id INTEGER NOT NULL REFERENCES users(user_id),"
        "  created_at  REAL    NOT NULL,"
        "  reasons     TEXT    NOT NULL DEFAULT 'NA',"
        "  PRIMARY KEY(channel_id, post_id, comment_id, reporter_id)"
        "  FOREIGN KEY(channel_id, post_id) REFERENCES posts(channel_id, post_id)"
        ")";
    memset(reported_comments_op.retrive_sql, 0, sizeof(reported_comments_op.retrive_sql));
    reported_comments_op.p_check = check_table_valid;
    reported_comments_op.p_del_idx = NULL;
    reported_comments_op.p_add_idx = NULL;
    operator_vec.push_back(&reported_comments_op);

    DBInitOperator tipping_op;
    tipping_op.item_num = 10;
    tipping_op.table_name = "tipping";
    tipping_op.idx_param = NULL;
    tipping_op.backup_sql = NULL;
    tipping_op.create_sql = "CREATE TABLE IF NOT EXISTS tipping ("
        "  id           INTEGER NOT NULL,"
        "  channel_id   INTEGER NOT NULL,"
        "  post_id      INTEGER NOT NULL,"
        "  created_at   REAL    NOT NULL,"
        "  token_mount  REAL    NOT NULL,"
        "  token_symbol TEXT    NOT NULL,"
        "  proof        TEXT    NOT NULL,"
        "  user_did     TEXT    NOT NULL,"
        "  user_name    TEXT    NOT NULL,"
        "  memo         TEXT    NOT NULL,"
        "  PRIMARY KEY(channel_id, post_id)"
        ")";
    memset(tipping_op.retrive_sql, 0, sizeof(tipping_op.retrive_sql));
    tipping_op.p_check = check_table_valid;
    tipping_op.p_del_idx = NULL;
    tipping_op.p_add_idx = NULL;
    operator_vec.push_back(&tipping_op);

    DBInitOperator notification_op;
    notification_op.item_num = 9;
    notification_op.table_name = "notification";
    notification_op.idx_param = NULL;
    notification_op.backup_sql = NULL;
    notification_op.create_sql = "CREATE TABLE IF NOT EXISTS notification ("
        "  notification_id INTEGER NOT NULL,"
        "  channel_id      INTEGER NOT NULL,"
        "  post_id         INTEGER NOT NULL,"
        "  comment_id      INTEGER NOT NULL,"
        "  action_type     INTEGER NOT NULL,"
        "  user_did        TEXT    NOT NULL,"
        "  user_name       TEXT    NOT NULL,"
        "  created_at      REAL    NOT NULL,"
        "  memo            TEXT    NOT NULL,"
        "  PRIMARY KEY(channel_id, post_id, comment_id)"
        ")";
    memset(notification_op.retrive_sql, 0, sizeof(notification_op.retrive_sql));
    notification_op.p_check = check_table_valid;
    notification_op.p_del_idx = NULL;
    notification_op.p_add_idx = NULL;
    operator_vec.push_back(&notification_op);

    /* ================== stmt-sep BEGIN ================== */
    if (-1 == sql_execution("BEGIN")) {
        vlogE(TAG_DB "BEGIN sql failed");
        return -1;
    }

    /* ================== stmt-sep operation ================== */
    int rc = -1;
    std::vector<DBInitOperator *>::iterator it = operator_vec.begin();
    for (; it != operator_vec.end(); ++it) {    //operate registered table one by one
        vlogD(TAG_DB "Begin to operate table %s ......", (*it)->table_name);
        rc = (*it)->p_check((*it)->table_name, (*it)->item_num);   //check table valid

        if (2 == rc) {    //table valid, do nothing
        } else if (1 == rc) {    //table exist but version is older
            vlogD(TAG_DB "Table %s is old version, updating", (*it)->table_name);
            if (-1 == sql_execution((*it)->backup_sql)) {    //backup failed 
                vlogE(TAG_DB "Backup table %s failed", (*it)->table_name);
                goto rollback;
            }
            vlogD(TAG_DB "Table %s backup done", (*it)->table_name);

            if (NULL != (*it)->p_del_idx) {    //del old index if needed
                if (-1 == (*it)->p_del_idx((*it)->table_name)) {
                    vlogE(TAG_DB "Delete table %s old index failed", (*it)->table_name);
                    goto rollback;
                }
                vlogD(TAG_DB "Delete table %s old index done", (*it)->table_name);
            }

            if (-1 == sql_execution((*it)->create_sql)) {    //create table failed
                vlogE(TAG_DB "Create table %s failed", (*it)->table_name);
                goto rollback;
            }
            vlogD(TAG_DB "Create table %s new version done", (*it)->table_name);

            if (NULL != (*it)->p_add_idx) {    //add new index if needed
                if (-1 == (*it)->p_add_idx((*it)->table_name, (*it)->idx_param)) {
                    vlogE(TAG_DB "Create table %s new index failed", (*it)->table_name);
                    goto rollback;
                }
                vlogD(TAG_DB "Create table %s new index done", (*it)->table_name);
            }

            if (-1 == sql_execution((*it)->retrive_sql)) {    //sync table data from backup
                vlogE(TAG_DB "Retrive table %s failed", (*it)->table_name);
                goto rollback;
            }
            vlogD(TAG_DB "Retrive table %s data done", (*it)->table_name);
        } else if (0 == rc) {    //table doesn't exist, create it
            vlogD(TAG_DB "Table %s did not exist, creating", (*it)->table_name);
            if (-1 == sql_execution((*it)->create_sql)) {    //create table failed
                vlogE(TAG_DB "Create table %s failed", (*it)->table_name);
                goto rollback;
            }
            vlogD(TAG_DB "Create table %s done", (*it)->table_name);

            if (NULL != (*it)->p_add_idx) {    //add new index if needed
                if (-1 == (*it)->p_add_idx((*it)->table_name, (*it)->idx_param)) {
                    vlogE(TAG_DB "Create table %s new index failed", (*it)->table_name);
                    goto rollback;
                }
                vlogD(TAG_DB "Create table %s new index done", (*it)->table_name);
            }
        } else {
            vlogE(TAG_DB "Check table %s valid failed", (*it)->table_name);
            goto rollback;
        }
    }

    /* ================== stmt-sep END ================== */
    if (-1 == sql_execution("END")) {
        vlogE(TAG_DB "END sql failed");
        goto rollback;
    }

    vlogI(TAG_DB "db init done");
    return 0;

    /* ================== ROLLBACK ================== */
rollback:
    vlogD(TAG_DB "Sth wrong, Ready to ROLLBACK");
    if (-1 == sql_execution("ROLLBACK"))
        vlogE(TAG_DB "ROLLBACK failed");

    return -1;
}

int db_create_chan(const ChanInfo *ci)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "INSERT INTO channels(created_at, updated_at,"
          " name, intro, avatar, iid, memo, tip_methods, proof) "
          " VALUES (:ts, :ts, :name, :intro, :avatar, 'NA', 'NA', :tip_methods, :proof)";
    //iid memo keep NA

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":ts"),
                            ci->created_at);
    rc |= sqlite3_bind_text(stmt,
                            sqlite3_bind_parameter_index(stmt, ":name"),
                            ci->name, -1, NULL);
    rc |= sqlite3_bind_text(stmt,
                            sqlite3_bind_parameter_index(stmt, ":intro"),
                            ci->intro, -1, NULL);
    rc |= sqlite3_bind_blob(stmt,
                            sqlite3_bind_parameter_index(stmt, ":avatar"),
                            ci->avatar, ci->len, NULL);
    rc |= sqlite3_bind_text(stmt,  //v2.0
                            sqlite3_bind_parameter_index(stmt, ":tip_methods"),
                            ci->tip_methods, -1, NULL);
    rc |= sqlite3_bind_text(stmt,  //v2.0
                            sqlite3_bind_parameter_index(stmt, ":proof"),
                            ci->proof, -1, NULL);
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "Inserting new channel failed");
        return -1;
    }

    return 0;
}

int db_upd_chan(const ChanInfo *ci)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "UPDATE channels"
          "  SET updated_at = :upd_at, name = :name, intro = :intro,"
          "  avatar = :avatar, tip_methods = :tipm, proof = :proof"
          "  WHERE channel_id = :channel_id";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":upd_at"),
                            ci->upd_at);
    rc |= sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":name"),
                           ci->name, -1, NULL);
    rc |= sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":intro"),
                           ci->intro, -1, NULL);
    rc |= sqlite3_bind_blob(stmt,
                           sqlite3_bind_parameter_index(stmt, ":avatar"),
                           ci->avatar, ci->len, NULL);
    rc |= sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":tipm"),
                           ci->tip_methods, -1, NULL);
    rc |= sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":proof"),
                           ci->proof, -1, NULL);
    rc |= sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":channel_id"),
                            ci->chan_id);
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "Updating new channel failed");
        return -1;
    }

    return 0;
}

int db_add_post(const PostInfo *pi)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "BEGIN";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "Executing BEIGIN failed");
        return -1;
    }

    do {
        sql = "INSERT INTO posts(channel_id, post_id, created_at, updated_at,"
            "  content, status, hash_id, proof, origin_post_url, thumbnails, iid, memo) "
            "  VALUES (:channel_id, :post_id, :ts, :ts, :content, :status,"
            "  :hash_id, :proof, :origin_post_url, :thumbnails, 'NA', 'NA')";  //2.0

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                pi->chan_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":post_id"),
                pi->post_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":ts"),
                pi->created_at);
        rc |= sqlite3_bind_blob(stmt,
                sqlite3_bind_parameter_index(stmt, ":content"),
                pi->content, pi->con_len, NULL);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":status"),
                pi->stat);
        rc |= sqlite3_bind_text(stmt,  //2.0
                sqlite3_bind_parameter_index(stmt, ":hash_id"),
                pi->hash_id, -1, NULL);
        rc |= sqlite3_bind_text(stmt,  //2.0
                sqlite3_bind_parameter_index(stmt, ":proof"),
                pi->proof, -1, NULL);
        rc |= sqlite3_bind_text(stmt,  //2.0
                sqlite3_bind_parameter_index(stmt, ":origin_post_url"),
                pi->origin_post_url, -1, NULL);
        rc |= sqlite3_bind_blob(stmt,  //2.0
                sqlite3_bind_parameter_index(stmt, ":thumbnails"),
                pi->thumbnails, pi->thu_len, NULL);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing INSERT into posts failed");
            break;
        }

        sql = "UPDATE channels "
            "  SET next_post_id = next_post_id + 1"
            "  WHERE channel_id = :channel_id";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                pi->chan_id);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter channel_id failed");
            sqlite3_finalize(stmt);
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing UPDATE failed");
            break;
        }

        sql = "END";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing END failed");
            break;
        }

        return 0;
    } while(0);

    sql = "ROLLBACK";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "ROLLBACK failed");
    }

    return -1;
}

int db_post_is_avail(uint64_t chan_id, uint64_t post_id)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "SELECT EXISTS(SELECT *"
          "                FROM posts"
          "                WHERE channel_id = :channel_id AND"
          "                      post_id = :post_id AND"
          "                      status = :avail)";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":channel_id"),
                            chan_id);
    rc |= sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":post_id"),
                            post_id);
    rc |= sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":avail"),
                            POST_AVAILABLE);
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    if (SQLITE_ROW != sqlite3_step(stmt)) {
        vlogE(TAG_DB "Executing SELECT failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    return rc ? 1 : 0;
}

int db_upd_post(PostInfo *pi)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "BEGIN";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "Executing BEIGIN failed");
        return -1;
    }

    do {
        sql = "UPDATE posts"
              "  SET updated_at = :upd_at, content = :content,"
              "  hash_id = :hash_id, proof = :proof,"  //2.0
              "  origin_post_url = :origin_post_url, thumbnails = :thumbnails"
              "  WHERE channel_id = :channel_id AND post_id = :post_id";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":upd_at"),
                pi->upd_at);
        rc |= sqlite3_bind_blob(stmt,
                sqlite3_bind_parameter_index(stmt, ":content"),
                pi->content, pi->con_len, NULL);
        rc |= sqlite3_bind_text(stmt,  //2.0
                sqlite3_bind_parameter_index(stmt, ":hash_id"),
                pi->hash_id, -1, NULL);
        rc |= sqlite3_bind_text(stmt,  //2.0
                sqlite3_bind_parameter_index(stmt, ":proof"),
                pi->proof, -1, NULL);
        rc |= sqlite3_bind_text(stmt,  //2.0
                sqlite3_bind_parameter_index(stmt, ":origin_post_url"),
                pi->origin_post_url, -1, NULL);
        rc |= sqlite3_bind_blob(stmt,  //2.0
                sqlite3_bind_parameter_index(stmt, ":thumbnails"),
                pi->thumbnails, pi->thu_len, NULL);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                pi->chan_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":post_id"),
                pi->post_id);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing UPDATE failed");
            break;
        }

        sql = "SELECT next_comment_id - 1 AS comments, likes, created_at"
              "  FROM posts"
              "  WHERE channel_id = :channel_id AND post_id = :post_id";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                pi->chan_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":post_id"),
                pi->post_id);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        rc = sqlite3_step(stmt);
        if (SQLITE_ROW != rc) {
            vlogE(TAG_DB "Executing SELECT failed");
            sqlite3_finalize(stmt);
            break;
        }

        pi->cmts       = sqlite3_column_int64(stmt, 0);
        pi->likes      = sqlite3_column_int64(stmt, 1);
        pi->created_at = sqlite3_column_int64(stmt, 2);
        sqlite3_finalize(stmt);

        sql = "END";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing END failed");
            break;
        }

        return 0;
    } while(0);

    sql = "ROLLBACK";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "ROLLBACK failed");
    }

    return -1;
}

int db_set_post_status(PostInfo *pi)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "BEGIN";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "Executing BEGIN failed");
        return -1;
    }

    do {
        sql = "UPDATE posts"
              "  SET status = :status"
              "  WHERE channel_id = :channel_id AND post_id = :post_id";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":status"),
                pi->stat);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                pi->chan_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":post_id"),
                pi->post_id);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing UPDATE failed");
            break;
        }

        sql = "SELECT next_comment_id - 1 AS comments, likes, created_at"
              "  FROM posts"
              "  WHERE channel_id = :channel_id AND post_id = :post_id";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                pi->chan_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":post_id"),
                pi->post_id);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        if (SQLITE_ROW != sqlite3_step(stmt)) {
            vlogE(TAG_DB "Executing SELECT failed");
            sqlite3_finalize(stmt);
            break;
        }

        pi->cmts       = sqlite3_column_int64(stmt, 0);
        pi->likes      = sqlite3_column_int64(stmt, 1);
        pi->created_at = sqlite3_column_int64(stmt, 2);
        sqlite3_finalize(stmt);

        sql = "END";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing END failed");
            break;
        }

        return 0;
    } while(0);

    sql = "ROLLBACK";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "ROLLBACK failed");
    }

    return -1;
}

int db_cmt_exists(uint64_t channel_id, uint64_t post_id, uint64_t comment_id)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "SELECT EXISTS( "
          "  SELECT * "
          "    FROM comments "
          "    WHERE channel_id = :channel_id AND "
          "          post_id = :post_id AND "
          "          comment_id = :comment_id"
          ")";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":channel_id"),
                            channel_id);
    rc |= sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":post_id"),
                            post_id);
    rc |= sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":comment_id"),
                            comment_id);
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    if (SQLITE_ROW != sqlite3_step(stmt)) {
        vlogE(TAG_DB "Executing SELECT failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    return rc ? 1 : 0;
}

int db_cmt_is_avail(uint64_t channel_id, uint64_t post_id, uint64_t comment_id)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "SELECT EXISTS(SELECT *"
          "                FROM comments"
          "                WHERE channel_id = :channel_id AND"
          "                      post_id = :post_id AND"
          "                      comment_id = :comment_id AND"
          "                      status = :avail)";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":channel_id"),
                            channel_id);
    rc |= sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":post_id"),
                            post_id);
    rc |= sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":comment_id"),
                            comment_id);
    rc |= sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":avail"),
                            CMT_AVAILABLE);
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    if (SQLITE_ROW != sqlite3_step(stmt)) {
        vlogE(TAG_DB "Executing SELECT failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    return rc ? 1 : 0;
}

int db_cmt_uid(uint64_t channel_id, uint64_t post_id, uint64_t comment_id, uint64_t *uid)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "SELECT user_id"
          "  FROM comments"
          "  WHERE channel_id = :channel_id AND"
          "        post_id = :post_id AND"
          "        comment_id = :comment_id";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_bind_int64(stmt,
            sqlite3_bind_parameter_index(stmt, ":channel_id"),
            channel_id);
    rc |= sqlite3_bind_int64(stmt,
            sqlite3_bind_parameter_index(stmt, ":post_id"),
            post_id);
    rc |= sqlite3_bind_int64(stmt,
            sqlite3_bind_parameter_index(stmt, ":comment_id"),
            comment_id);
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    if (SQLITE_ROW != sqlite3_step(stmt)) {
        vlogE(TAG_DB "Executing SELECT failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    *uid = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);

    return 0;
}

int db_add_cmt(CmtInfo *ci, uint64_t *id)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "BEGIN";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "Executing BEGIN failed");
        return -1;
    }

    do {
        sql = "INSERT INTO comments("
              "  channel_id, post_id, comment_id, "
              "  refcomment_id, user_id, created_at, updated_at, content,"
              "  hash_id, proof, thumbnails, iid, memo"  //2.0
              ") VALUES ("
              "  :channel_id, :post_id, "
              "  (SELECT next_comment_id "
              "     FROM posts "
              "     WHERE channel_id = :channel_id AND "
              "           post_id = :post_id), "
              "  :comment_id, :uid, :ts, :ts, :content, :hash_id, :proof, :thumbnails, 'NA', 'NA'"
              ")";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                ci->chan_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":post_id"),
                ci->post_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":comment_id"),
                ci->reply_to_cmt);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":uid"),
                ci->user.uid);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":ts"),
                ci->created_at);
        rc |= sqlite3_bind_blob(stmt,
                sqlite3_bind_parameter_index(stmt, ":content"),
                ci->content, ci->con_len, NULL);
        rc |= sqlite3_bind_text(stmt,  //2.0
                sqlite3_bind_parameter_index(stmt, ":hash_id"),
                ci->hash_id, -1, NULL);
        rc |= sqlite3_bind_text(stmt,  //2.0
                sqlite3_bind_parameter_index(stmt, ":proof"),
                ci->proof, -1, NULL);
        rc |= sqlite3_bind_blob(stmt,  //2.0
                sqlite3_bind_parameter_index(stmt, ":thumbnails"),
                ci->thumbnails, ci->thu_len, NULL);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing INSERT failed");
            break;
        }

        sql = "UPDATE posts "
              "  SET next_comment_id = next_comment_id + 1 "
              "  WHERE channel_id = :channel_id AND post_id = :post_id";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                ci->chan_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":post_id"),
                ci->post_id);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing UPDATE failed");
            break;
        }

        sql = "SELECT next_comment_id - 1 "
              "  FROM posts "
              "  WHERE channel_id = :channel_id AND post_id = :post_id";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                ci->chan_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":post_id"),
                ci->post_id);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        if (SQLITE_ROW != sqlite3_step(stmt)) {
            vlogE(TAG_DB "Executing SELECT failed");
            sqlite3_finalize(stmt);
            break;
        }

        *id = sqlite3_column_int64(stmt, 0);
        sqlite3_finalize(stmt);

        sql = "END";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing END failed");
            break;
        }

        return 0;
    } while(0);

    sql = "ROLLBACK";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "ROLLBACK failed");
    }

    return -1;
}

int db_get_post_status(uint64_t chan_id, uint64_t post_id)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;
    PostStat stat;

    sql = "BEGIN";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "Executing BEGIN failed");
        return -1;
    }

    do {
        sql = "SELECT status"
              "  FROM posts"
              "  WHERE channel_id = :channel_id AND post_id = :post_id";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                chan_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":post_id"),
                post_id);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        if (SQLITE_ROW != sqlite3_step(stmt)) {
            vlogE(TAG_DB "Executing SELECT failed");
            sqlite3_finalize(stmt);
            break;
        }

        stat = (PostStat)sqlite3_column_int64(stmt, 0);
        sqlite3_finalize(stmt);

        sql = "END";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing END failed");
            break;
        }

        return stat;
    } while(0);

    sql = "ROLLBACK";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "ROLLBACK failed");
    }

    return -1;
}

int db_get_post(uint64_t chan_id, uint64_t post_id, PostInfo *pi)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "BEGIN";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "Executing BEGIN failed");
        return -1;
    }

    do {
        sql = "SELECT status, content, length(content), "
              "       next_comment_id - 1 AS comments, likes, created_at, updated_at, "
              "       thumbnails, length(thumbnails), hash_id, proof, origin_post_url"
              "  FROM posts "
              "  WHERE channel_id = :channel_id AND post_id = :post_id";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                chan_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":post_id"),
                post_id);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        if (SQLITE_ROW != sqlite3_step(stmt)) {
            vlogE(TAG_DB "Executing SELECT failed");
            sqlite3_finalize(stmt);
            break;
        }

        pi->stat = (PostStat)sqlite3_column_int64(stmt, 0);
        const void* content = sqlite3_column_blob(stmt, 1); 
        int content_size = sqlite3_column_int64(stmt, 2); 
        pi->content = rc_zalloc(content_size, NULL);
        memcpy(pi->content, content, content_size);
        pi->con_len = content_size;
        pi->cmts = sqlite3_column_int64(stmt, 3); 
        pi->likes = sqlite3_column_int64(stmt, 4); 
        pi->created_at = sqlite3_column_int64(stmt, 5);
        pi->upd_at = sqlite3_column_int64(stmt, 6);
        const void* thumbnails = sqlite3_column_blob(stmt, 7);
        int thumbnails_size = sqlite3_column_int64(stmt, 8);
        pi->thumbnails = rc_zalloc(thumbnails_size, NULL);
        pi->thu_len = thumbnails_size;
        memcpy(pi->thumbnails, thumbnails, thumbnails_size);

        char *tmp = (char *)sqlite3_column_text(stmt, 9);
        char *hash_id = (char *)rc_zalloc(strlen(tmp) + 1, NULL);
        pi->hash_id = strcpy(hash_id, tmp);

        tmp = (char *)sqlite3_column_text(stmt, 10);
        char *proof = (char *)rc_zalloc(strlen(tmp) + 1, NULL);
        pi->proof = strcpy(proof, tmp);

        tmp = (char *)sqlite3_column_text(stmt, 11);
        char *origin_post_url = (char *)rc_zalloc(strlen(tmp) + 1, NULL);
        pi->origin_post_url = strcpy(origin_post_url, tmp);
        sqlite3_finalize(stmt);

        sql = "END";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing END failed");
            break;
        }

        return 0;
    } while(0);

    sql = "ROLLBACK";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "ROLLBACK failed");
    }

    return -1;
}

int db_upd_cmt(CmtInfo *ci)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "BEGIN";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "Executing BEGIN failed");
        return -1;
    }

    do {
        sql = "UPDATE comments"
              "  SET updated_at = :upd_at, content = :content,"
              "  refcomment_id = :ref_cmt_id, hash_id = :hash_id,"  //2.0
              "  proof = :proof, thumbnails = :thumbnails"
              "  WHERE channel_id = :channel_id AND post_id = :post_id"
              "  AND comment_id = :comment_id";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":upd_at"),
                ci->upd_at);
        rc |= sqlite3_bind_blob(stmt,
                sqlite3_bind_parameter_index(stmt, ":content"),
                ci->content, ci->con_len, NULL);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":ref_cmt_id"),
                ci->reply_to_cmt);
        rc |= sqlite3_bind_text(stmt,  //2.0
                sqlite3_bind_parameter_index(stmt, ":hash_id"),
                ci->hash_id, -1, NULL);
        rc |= sqlite3_bind_text(stmt,  //2.0
                sqlite3_bind_parameter_index(stmt, ":proof"),
                ci->proof, -1, NULL);
        rc |= sqlite3_bind_blob(stmt,  //2.0
                sqlite3_bind_parameter_index(stmt, ":thumbnails"),
                ci->thumbnails, ci->thu_len, NULL);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                ci->chan_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":post_id"),
                ci->post_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":comment_id"),
                ci->cmt_id);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing UPDATE failed");
            break;
        }

        sql = "SELECT likes, created_at"
              "  FROM comments"
              "  WHERE channel_id = :channel_id AND post_id = :post_id AND comment_id = :comment_id";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                ci->chan_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":post_id"),
                ci->post_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":comment_id"),
                ci->cmt_id);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        if (SQLITE_ROW != sqlite3_step(stmt)) {
            vlogE(TAG_DB "Executing SELECT failed");
            sqlite3_finalize(stmt);
            break;
        }

        ci->likes      = sqlite3_column_int64(stmt, 0);
        ci->created_at = sqlite3_column_int64(stmt, 1);
        sqlite3_finalize(stmt);


        sql = "END";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing END failed");
            break;
        }

        return 0;
    } while(0);

    sql = "ROLLBACK";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "ROLLBACK failed");
    }

    return -1;
}

int db_set_cmt_status(CmtInfo *ci)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "BEGIN";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "Executing BEGIN failed");
        return -1;
    }

    do {
        sql = "UPDATE comments"
              "  SET updated_at = :upd_at, status = :deleted"
              "  WHERE channel_id = :channel_id AND post_id = :post_id AND comment_id = :comment_id";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":upd_at"),
                ci->upd_at);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":deleted"),
                ci->stat);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                ci->chan_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":post_id"),
                ci->post_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":comment_id"),
                ci->cmt_id);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing UPDATE failed");
            break;
        }

        sql = "SELECT refcomment_id, likes, created_at"
              "  FROM comments"
              "  WHERE channel_id = :channel_id AND post_id = :post_id AND comment_id = :comment_id";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                ci->chan_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":post_id"),
                ci->post_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":comment_id"),
                ci->cmt_id);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        if (SQLITE_ROW != sqlite3_step(stmt)) {
            vlogE(TAG_DB "Executing SELECT failed");
            sqlite3_finalize(stmt);
            break;
        }

        ci->reply_to_cmt = sqlite3_column_int64(stmt, 0);
        ci->likes        = sqlite3_column_int64(stmt, 1);
        ci->created_at   = sqlite3_column_int64(stmt, 2);
        sqlite3_finalize(stmt);

        sql = "END";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing END failed");
            break;
        }

        return 0;
    } while(0);

    sql = "ROLLBACK";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "ROLLBACK failed");
    }

    return -1;
}

int db_like_exists(uint64_t uid, uint64_t channel_id, uint64_t post_id, uint64_t comment_id)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "SELECT EXISTS(SELECT * "
          "                FROM likes "
          "                WHERE user_id = :uid AND "
          "                      channel_id = :channel_id AND "
          "                      post_id = :post_id AND "
          "                      comment_id = :comment_id)";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_bind_int64(stmt,
            sqlite3_bind_parameter_index(stmt, ":uid"),
            uid);
    rc |= sqlite3_bind_int64(stmt,
            sqlite3_bind_parameter_index(stmt, ":channel_id"),
            channel_id);
    rc |= sqlite3_bind_int64(stmt,
            sqlite3_bind_parameter_index(stmt, ":post_id"),
            post_id);
    rc |= sqlite3_bind_int64(stmt,
            sqlite3_bind_parameter_index(stmt, ":comment_id"),
            comment_id);
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    if (SQLITE_ROW != sqlite3_step(stmt)) {
        vlogE(TAG_DB "Executing SELECT failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    return rc ? 1 : 0;
}

int db_add_like(uint64_t uid, uint64_t channel_id, uint64_t post_id,
        uint64_t comment_id, const char *proof, uint64_t *likes)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "BEGIN";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "Exectuing BEGIN failed");
        return -1;
    }

    do {
        sql = comment_id ?
            "UPDATE comments "
            "  SET likes = likes + 1 "
            "  WHERE channel_id = :channel_id AND "
            "        post_id = :post_id AND "
            "        comment_id = :comment_id" :
            "UPDATE posts "
            "  SET likes = likes + 1 "
            "  WHERE channel_id = :channel_id AND "
            "        post_id = :post_id";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                channel_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":post_id"),
                post_id);
        if (comment_id) {
            rc |= sqlite3_bind_int64(stmt,
                    sqlite3_bind_parameter_index(stmt, ":comment_id"),
                    comment_id);
        }
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing UPDATE failed");
            break;
        }

        sql = "INSERT INTO likes(user_id, channel_id, post_id, comment_id,"
              "created_at, proof, memo) "
              "  VALUES (:uid, :channel_id, :post_id, :comment_id, :ts, :proof, 'NA')";
        //keep memo NA 

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":uid"),
                uid);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                channel_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":post_id"),
                post_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":comment_id"),
                comment_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":ts"),
                time(NULL));
        rc |= sqlite3_bind_text(stmt,  //2.0
                sqlite3_bind_parameter_index(stmt, ":proof"),
                proof, -1, NULL);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing INSERT failed");
            break;
        }

        sql = comment_id ?
            "SELECT likes "
            "  FROM comments "
            "  WHERE channel_id = :channel_id AND "
            "        post_id = :post_id AND "
            "        comment_id = :comment_id" :
            "SELECT likes "
            "  FROM posts "
            "  WHERE channel_id = :channel_id AND "
            "        post_id = :post_id";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                channel_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":post_id"),
                post_id);
        if (comment_id) {
            rc |= sqlite3_bind_int64(stmt,
                    sqlite3_bind_parameter_index(stmt, ":comment_id"),
                    comment_id);
        }
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        if (SQLITE_ROW != sqlite3_step(stmt)) {
            vlogE(TAG_DB "Executing SELECT failed");
            sqlite3_finalize(stmt);
            break;
        }

        *likes = sqlite3_column_int64(stmt, 0);
        sqlite3_finalize(stmt);

        sql = "END";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing END failed");
            break;
        }

        return 0;
    } while(0);

    sql = "ROLLBACK";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "ROLLBACK failed");
    }

    return -1;
}

int db_rm_like(uint64_t uid, uint64_t channel_id, uint64_t post_id, uint64_t comment_id)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "BEGIN";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "Executing BEGIN failed");
        return -1;
    }

    do {
        sql = comment_id ?
            "UPDATE comments "
            "  SET likes = likes - 1 "
            "  WHERE channel_id = :channel_id AND "
            "        post_id = :post_id AND "
            "        comment_id = :comment_id" :
            "UPDATE posts "
            "  SET likes = likes - 1 "
            "  WHERE channel_id = :channel_id AND "
            "        post_id = :post_id";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                channel_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":post_id"),
                post_id);
        if (comment_id) {
            rc |= sqlite3_bind_int64(stmt,
                    sqlite3_bind_parameter_index(stmt, ":comment_id"),
                    comment_id);
        }
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing UPDATE failed");
            break;
        }

        sql = "DELETE FROM likes "
              "  WHERE user_id = :uid AND channel_id = :channel_id AND "
              "        post_id = :post_id AND comment_id = :comment_id";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":uid"),
                uid);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                channel_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":post_id"),
                post_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":comment_id"),
                comment_id);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing DELETE failed");
            break;
        }

        sql = "END";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing END failed");
            break;
        }

        return 0;
    } while(0);

    sql = "ROLLBACK";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "ROLLBACK failed");
    }

    return -1;
}

int db_add_sub(uint64_t uid, uint64_t channel_id, const char *proof)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "BEGIN";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "Executing BEGIN failed");
        return -1;
    }

    do {
        sql = "INSERT INTO subscriptions(user_id, channel_id, create_at, proof, memo)"
              "  VALUES (:uid, :channel_id, :create_at, :proof, 'NA')";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":uid"),
                uid);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                channel_id);
        rc |= sqlite3_bind_int64(stmt,  //v2.0
                sqlite3_bind_parameter_index(stmt, ":create_at"),
                time(NULL));
        rc |= sqlite3_bind_text(stmt,  //v2.0
                sqlite3_bind_parameter_index(stmt, ":proof"),
                proof, -1, NULL);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing INSERT failed (%d)", __LINE__);
            break;
        }

        sql = "UPDATE channels "
              "  SET subscribers = subscribers + 1"
              "  WHERE channel_id = :channel_id";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                channel_id);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing UPDATE failed (%d)", __LINE__);
            break;
        }

        sql = "END";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing END failed");
            break;
        }

        return 0;
    } while(0);

    sql = "ROLLBACK";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "ROLLBACK failed");
    }

    return -1;
}

int db_unsub(uint64_t uid, uint64_t channel_id)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "BEGIN";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "Executing BEGIN failed");
        return -1;
    }

    do {
        sql = "DELETE FROM subscriptions "
              "  WHERE user_id = :uid AND channel_id = :channel_id";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":uid"),
                uid);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                channel_id);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing DELETE failed");
            break;
        }

        sql = "UPDATE channels "
              "  SET subscribers = subscribers - 1"
              "  WHERE channel_id = :channel_id";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                channel_id);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing UPDATE failed");
            break;
        }

        sql = "END";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing END failed");
            break;
        }

        return 0;
    } while(0);

    sql = "ROLLBACK";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "ROLLBACK failed");
    }

    return -1;
}

int db_update_user_info(const UserInfo *ui)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "UPDATE users"
        "  SET name = :name, email = :email, display_name = :display_name,"
        "  avatar = :avatar, update_at = :upd_at, memo = 'NA'"
        "  WHERE did = :did";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_bind_text(stmt,
            sqlite3_bind_parameter_index(stmt, ":did"),
            ui->did, -1, NULL);
    rc |= sqlite3_bind_text(stmt,
            sqlite3_bind_parameter_index(stmt, ":name"),
            ui->name, -1, NULL);
    rc |= sqlite3_bind_text(stmt,
            sqlite3_bind_parameter_index(stmt, ":email"),
            ui->email, -1, NULL);
    rc |= sqlite3_bind_text(stmt,
            sqlite3_bind_parameter_index(stmt, ":display_name"),
            ui->display_name, -1, NULL);
    rc |= sqlite3_bind_blob(stmt,
            sqlite3_bind_parameter_index(stmt, ":avatar"),
            ui->avatar, ui->len, NULL);
    rc |= sqlite3_bind_int64(stmt,  //v2.0
            sqlite3_bind_parameter_index(stmt, ":upd_at"),
            time(NULL));
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "Executing INSERT failed");
        return -1;
    }

    return 0;
}


int db_upsert_user(const UserInfo *ui, uint64_t *uid)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "INSERT INTO users(did, name, email, display_name, update_at, memo, avatar)"
          " VALUES (:did, :name, :email, :display_name, :upd_at, 'NA', :avatar)"
          " ON CONFLICT (did) "
          " DO UPDATE "
          "       SET name = :name, email = :email "
          "       WHERE excluded.name IS NOT name OR excluded.email IS NOT email";
    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_bind_text(stmt,
            sqlite3_bind_parameter_index(stmt, ":did"),
            ui->did, -1, NULL);
    rc |= sqlite3_bind_text(stmt,
            sqlite3_bind_parameter_index(stmt, ":name"),
            ui->name, -1, NULL);
    rc |= sqlite3_bind_text(stmt,
            sqlite3_bind_parameter_index(stmt, ":email"),
            ui->email, -1, NULL);
    if (NULL != ui->display_name) {
        rc |= sqlite3_bind_text(stmt,
                sqlite3_bind_parameter_index(stmt, ":display_name"),
                ui->display_name, -1, NULL);
    } else {
        rc |= sqlite3_bind_text(stmt,
                sqlite3_bind_parameter_index(stmt, ":display_name"),
                "NA", -1, NULL);
    }
    rc |= sqlite3_bind_int64(stmt,  //v2.0
            sqlite3_bind_parameter_index(stmt, ":upd_at"),
            time(NULL));
    if (NULL != ui->avatar) {
        rc |= sqlite3_bind_blob(stmt,  //2.0
                sqlite3_bind_parameter_index(stmt, ":avatar"),
                ui->avatar, ui->len, NULL);
    } else {
        const char n = 0xA0;
        rc |= sqlite3_bind_blob(stmt,  //2.0
                sqlite3_bind_parameter_index(stmt, ":avatar"),
                &n, 1, NULL);
    }
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "Executing INSERT failed");
        return -1;
    }

    sql = "SELECT user_id FROM users WHERE did = :did";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_bind_text(stmt,
            sqlite3_bind_parameter_index(stmt, ":did"),
            ui->did, -1, NULL);
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter did failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    if (SQLITE_ROW != sqlite3_step(stmt)) {
        vlogE(TAG_DB "Executing SELECT failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    *uid = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);

    return 0;
}

typedef enum {
    CHANNEL,
    POST,
    COMMENT
} QueryObject;

static
const char *query_column(QueryObject qo, QryFld qf)
{
    switch (qf) {
        case ID:
            switch (qo) {
                case CHANNEL:
                    return "channel_id";
                case POST:
                    return "post_id";
                case COMMENT:
                    return "comment_id";
                default:
                    return NULL;
            }
        case UPD_AT:
            return "updated_at";
        case CREATED_AT:
            return "created_at";
        default:
            return NULL;
    }
}

static
void it_dtor(void *obj)
{
    DBObjIt *it = (DBObjIt *)obj;

    if (it->stmt)
        sqlite3_finalize(it->stmt);
}

static
DBObjIt *it_create(sqlite3_stmt *stmt, Row2Raw cb)
{
    DBObjIt *it = (DBObjIt *)rc_zalloc(sizeof(DBObjIt), it_dtor);
    if (!it)
        return NULL;

    it->stmt = stmt;
    it->cb   = cb;

    return it;
}

static
void *row2chan(sqlite3_stmt *stmt)
{
    const char *name = (const char *)sqlite3_column_text(stmt, 1);
    const char *intro = (const char *)sqlite3_column_text(stmt, 2);
    size_t avatar_sz = sqlite3_column_int64(stmt, 8);
    const char *tipm = (const char *)sqlite3_column_text(stmt, 9);
    const char *proof = (const char *)sqlite3_column_text(stmt, 10);
    ChanInfo *ci = (ChanInfo *)rc_zalloc(sizeof(ChanInfo) + strlen(name) + 
            strlen(intro) + strlen(tipm) + strlen(proof) + 4 + avatar_sz, NULL);
    void *buf;

    if (!ci) {
        vlogE(TAG_DB "OOM");
        return NULL;
    }

    buf = ci + 1;

    ci->chan_id      = sqlite3_column_int64(stmt, 0);
    ci->name         = strcpy((char *)buf, name);
    buf = (char *)buf + strlen(name) + 1;
    ci->intro        = strcpy((char *)buf, intro);
    buf = (char *)buf + strlen(intro) + 1;
    ci->subs         = sqlite3_column_int64(stmt, 3);
    ci->next_post_id = sqlite3_column_int64(stmt, 4);
    ci->upd_at       = sqlite3_column_int64(stmt, 5);
    ci->created_at   = sqlite3_column_int64(stmt, 6);
    ci->owner        = &feeds_owner_info;
    ci->avatar       = memcpy(buf, sqlite3_column_blob(stmt, 7), avatar_sz);
    buf = (char *)buf + avatar_sz;
    ci->len          = avatar_sz;
    ci->tip_methods  = strcpy((char *)buf, tipm);
    buf = (char *)buf + strlen(tipm) + 1;
    ci->proof        = strcpy((char *)buf, proof);
    ci->status       = sqlite3_column_int64(stmt, 11);

    return ci;
}

DBObjIt *db_iter_chans(const QryCriteria *qc)
{
    sqlite3_stmt *stmt;
    const char *qcol;
    char sql[1024] = {0};
    DBObjIt *it;
    int rc;

    rc = sprintf(sql,
            "SELECT channel_id, name, intro, subscribers,"
            " next_post_id, updated_at, created_at, avatar,"
            " length(avatar), tip_methods, proof, status"
            " FROM channels");
    if (qc->by) {
        qcol = query_column(CHANNEL, (QryFld)qc->by);
        if (qc->lower || qc->upper)
            rc += sprintf(sql + rc, " WHERE ");
        if (qc->lower)
            rc += sprintf(sql + rc, "%s >= :lower", qcol);
        if (qc->upper)
            rc += sprintf(sql + rc, "%s %s <= :upper", qc->lower ? " AND" : "", qcol);
        rc += sprintf(sql + rc, " ORDER BY %s %s", qcol, qc->by == ID ? "ASC" : "DESC");
    }
    if (qc->maxcnt)
        rc += sprintf(sql + rc, " LIMIT :maxcnt");

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return NULL;
    }

    if (qc->lower) {
        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":lower"),
                qc->lower);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter lower failed");
            sqlite3_finalize(stmt);
            return NULL;
        }
    }

    if (qc->upper) {
        rc = sqlite3_bind_int64(stmt,
                                sqlite3_bind_parameter_index(stmt, ":upper"),
                                qc->upper);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter upper failed");
            sqlite3_finalize(stmt);
            return NULL;
        }
    }

    if (qc->maxcnt) {
        rc = sqlite3_bind_int64(stmt,
                                sqlite3_bind_parameter_index(stmt, ":maxcnt"),
                                qc->maxcnt);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter maxcnt failed");
            sqlite3_finalize(stmt);
            return NULL;
        }
    }

    it = it_create(stmt, row2chan);
    if (!it) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    return it;
}

static
void *row2subchan(sqlite3_stmt *stmt)
{
    const char *name = (const char *)sqlite3_column_text(stmt, 1);
    const char *intro = (const char *)sqlite3_column_text(stmt, 2);
    size_t avatar_sz = sqlite3_column_int64(stmt, 7);
    const char *proof = (const char *)sqlite3_column_text(stmt, 8);

    ChanInfo *ci = (ChanInfo *)rc_zalloc(sizeof(ChanInfo) 
            + strlen(name) + strlen(intro) + strlen(proof) + 3 + avatar_sz, NULL);
    void *buf;

    if (!ci) {
        vlogE(TAG_DB "OOM");
        return NULL;
    }

    buf = ci + 1;
    ci->chan_id = sqlite3_column_int64(stmt, 0);
    ci->name    = strcpy((char *)buf, name);
    buf = (char *)buf + strlen(name) + 1;
    ci->intro   = strcpy((char *)buf, intro);
    buf = (char *)buf + strlen(intro) + 1;
    ci->proof   = strcpy((char *)buf, proof);
    buf = (char *)buf + strlen(proof) + 1;
    ci->subs    = sqlite3_column_int64(stmt, 3);
    ci->created_at  = sqlite3_column_int64(stmt, 4);
    ci->upd_at  = sqlite3_column_int64(stmt, 5);
    ci->owner   = &feeds_owner_info;
    ci->avatar  = memcpy(buf, sqlite3_column_blob(stmt, 6), avatar_sz);
    ci->len     = avatar_sz;

    return ci;
}

DBObjIt *db_iter_sub_chans(uint64_t uid, const QryCriteria *qc)
{
    sqlite3_stmt *stmt;
    const char *qcol;
    char sql[1024] = {0};
    DBObjIt *it;
    int rc;

    rc = sprintf(sql,
                 "SELECT channel_id, name, intro, subscribers, created_at, updated_at,"
                 "  avatar, length(avatar), proof"
                 "  FROM (SELECT channel_id "
                 "          FROM subscriptions "
                 "          WHERE user_id = :uid) JOIN channels USING (channel_id)");
    if (qc->by) {
        qcol = query_column(CHANNEL, (QryFld)qc->by);
        if (qc->lower || qc->upper)
            rc += sprintf(sql + rc, " WHERE ");
        if (qc->lower)
            rc += sprintf(sql + rc, "%s >= :lower", qcol);
        if (qc->upper)
            rc += sprintf(sql + rc, "%s %s <= :upper", qc->lower ? " AND" : "", qcol);
        rc += sprintf(sql + rc, " ORDER BY %s %s", qcol, qc->by == ID ? "ASC" : "DESC");
    }
    if (qc->maxcnt)
        rc += sprintf(sql +rc, " LIMIT :maxcnt");

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return NULL;
    }

    rc = sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":uid"),
                            uid);
    if (qc->lower) {
        rc |= sqlite3_bind_int64(stmt,
                                sqlite3_bind_parameter_index(stmt, ":lower"),
                                qc->lower);
    }
    if (qc->upper) {
        rc |= sqlite3_bind_int64(stmt,
                                sqlite3_bind_parameter_index(stmt, ":upper"),
                                qc->upper);
    }
    if (qc->maxcnt) {
        rc |= sqlite3_bind_int64(stmt,
                                sqlite3_bind_parameter_index(stmt, ":maxcnt"),
                                qc->maxcnt);
    }
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter failed");
        sqlite3_finalize(stmt);
        return NULL;
    }

    it = it_create(stmt, row2subchan);
    if (!it) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    return it;
}

static
void *row2post(sqlite3_stmt *stmt)
{
    PostStat stat = (PostStat)sqlite3_column_int64(stmt, 2);
    size_t con_len = (stat != POST_AVAILABLE ? 0 : sqlite3_column_int64(stmt, 4));
    size_t thu_len = (stat != POST_AVAILABLE ? 0 : sqlite3_column_int64(stmt, 13));  //2.0
    const char *hash_id = (const char *)sqlite3_column_text(stmt, 9);  //2.0
    const char *proof = (const char *)sqlite3_column_text(stmt, 10);  //2.0
    const char *origin_post_url = (const char *)sqlite3_column_text(stmt, 11);  //2.0
    void *buf;

    PostInfo *pi = (PostInfo *)rc_zalloc(sizeof(PostInfo) + con_len + thu_len +
            strlen(hash_id) + strlen(proof) + strlen(origin_post_url) + 5, NULL);  //2.0
    if (!pi) {
        vlogE(TAG_DB "OOM");
        return NULL;
    }

    pi->chan_id     = sqlite3_column_int64(stmt, 0);
    pi->post_id     = sqlite3_column_int64(stmt, 1);
    pi->stat        = stat;
    pi->cmts        = sqlite3_column_int64(stmt, 5);
    pi->likes       = sqlite3_column_int64(stmt, 6);
    pi->created_at  = sqlite3_column_int64(stmt, 7);
    pi->upd_at      = sqlite3_column_int64(stmt, 8);
    buf = pi + 1;  //2.0
    pi->hash_id     = strcpy((char *)buf, hash_id);  //2.0
    buf = (char *)buf + strlen(hash_id) + 1;  //2.0
    pi->proof       = strcpy((char *)buf, proof);  //2.0
    buf = (char *)buf + strlen(proof) + 1;  //2.0
    pi->origin_post_url = strcpy((char *)buf, origin_post_url);  //2.0
    if (stat == POST_AVAILABLE) {
        buf = (char *)buf + strlen(origin_post_url) + 1;
        pi->content = memcpy(buf, sqlite3_column_blob(stmt, 3), con_len);
        pi->con_len = con_len;
        buf = (char *)buf + con_len + 1;   //2.0
        pi->thumbnails = memcpy(buf, sqlite3_column_blob(stmt, 12), thu_len);  //2.0
        pi->thu_len = thu_len;  //2.0
    }

    return pi;
}

DBObjIt *db_iter_posts(uint64_t chan_id, const QryCriteria *qc)
{
    sqlite3_stmt *stmt;
    const char *qcol;
    char sql[1024] = {0};
    DBObjIt *it;
    int rc;

    rc = sprintf(sql,
                 "SELECT channel_id, post_id, status, content, length(content),"
                 "       next_comment_id - 1 AS comments, likes, created_at,"
                 "       updated_at, hash_id, proof, origin_post_url, thumbnails,"
                 "       length(thumbnails)"
                 "  FROM posts "
                 "  WHERE channel_id = :channel_id");  //2.0
    rc += sprintf(sql + rc, " AND (status=%d OR status=%d)", POST_AVAILABLE, POST_DELETED);
    if (qc->by) {
        qcol = query_column(POST, (QryFld)qc->by);
        if (qc->lower)
            rc += sprintf(sql + rc, " AND %s >= :lower", qcol);
        if (qc->upper)
            rc += sprintf(sql + rc, " AND %s <= :upper", qcol);
        rc += sprintf(sql + rc, " ORDER BY %s %s", qcol, qc->by == ID ? "ASC" : "DESC");
    }
    if (qc->maxcnt)
        rc += sprintf(sql + rc, " LIMIT :maxcnt");

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return NULL;
    }

    rc = sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":channel_id"),
                            chan_id);
    if (qc->lower) {
        rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":lower"),
                                qc->lower);
    }
    if (qc->upper) {
        rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":upper"),
                                qc->upper);
    }
    if (qc->maxcnt) {
        rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":maxcnt"),
                                qc->maxcnt);
    }
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter channel_id failed");
        sqlite3_finalize(stmt);
        return NULL;
    }

    it = it_create(stmt, row2post);
    if (!it) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    char* exsql = sqlite3_expanded_sql(stmt);
    vlogD(TAG_DB "get posts sql: %s", exsql);
    sqlite3_free(exsql);

    return it;
}

static
void *row2postlac(sqlite3_stmt *stmt)
{
    PostInfo *pi = (PostInfo *)rc_zalloc(sizeof(PostInfo), NULL);
    if (!pi) {
        vlogE(TAG_DB "OOM");
        return NULL;
    }

    pi->chan_id = sqlite3_column_int64(stmt, 0);
    pi->post_id = sqlite3_column_int64(stmt, 1);
    pi->cmts    = sqlite3_column_int64(stmt, 2);
    pi->likes   = sqlite3_column_int64(stmt, 3);

    return pi;
}

DBObjIt *db_iter_posts_lac(uint64_t chan_id, const QryCriteria *qc)
{
    sqlite3_stmt *stmt;
    const char *qcol;
    char sql[1024] = {0};
    DBObjIt *it;
    int rc;

    rc = sprintf(sql,
                 "SELECT channel_id, post_id, next_comment_id - 1 AS comments, likes"
                 "  FROM posts "
                 "  WHERE channel_id = :channel_id");
    if (qc->by) {
        qcol = query_column(POST, (QryFld)qc->by);
        if (qc->lower)
            rc += sprintf(sql + rc, " AND %s >= :lower", qcol);
        if (qc->upper)
            rc += sprintf(sql + rc, " AND %s <= :upper", qcol);
        rc += sprintf(sql + rc, " ORDER BY %s %s", qcol, qc->by == ID ? "ASC" : "DESC");
    }
    if (qc->maxcnt)
        rc += sprintf(sql + rc, " LIMIT :maxcnt");

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return NULL;
    }

    rc = sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":channel_id"),
                            chan_id);
    if (qc->lower) {
        rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":lower"),
                                qc->lower);
    }
    if (qc->upper) {
        rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":upper"),
                                qc->upper);
    }
    if (qc->maxcnt) {
        rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":maxcnt"),
                                qc->maxcnt);
    }
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter channel_id failed");
        sqlite3_finalize(stmt);
        return NULL;
    }

    it = it_create(stmt, row2postlac);
    if (!it) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    return it;
}

static
void *row2likedpost(sqlite3_stmt *stmt)
{
    size_t len = sqlite3_column_int64(stmt, 3);
    PostInfo *pi = (PostInfo *)rc_zalloc(sizeof(PostInfo) + len, NULL);
    void *buf;

    if (!pi) {
        vlogE(TAG_DB "OOM");
        return NULL;
    }

    pi->chan_id    = sqlite3_column_int64(stmt, 0);
    pi->post_id    = sqlite3_column_int64(stmt, 1);
    buf = pi + 1;
    pi->content    = memcpy(buf, sqlite3_column_blob(stmt, 2), len);
    pi->con_len    = len;
    pi->cmts       = sqlite3_column_int64(stmt, 4);
    pi->likes      = sqlite3_column_int64(stmt, 5);
    pi->created_at = sqlite3_column_int64(stmt, 6);

    return pi;
}

DBObjIt *db_iter_liked_posts(uint64_t uid, const QryCriteria *qc)
{
    sqlite3_stmt *stmt;
    const char *qcol;
    char sql[1024] = {0};
    DBObjIt *it;
    int rc;

    rc = sprintf(sql,
                 "SELECT channel_id, post_id, content, length(content), "
                 "       next_comment_id - 1 AS comments, likes, created_at "
                 "  FROM (SELECT channel_id, post_id "
                 "          FROM likes "
                 "          WHERE user_id = :uid AND comment_id = 0) JOIN "
                 "       posts USING (channel_id, post_id)"
                 "  WHERE status = :avail");
    if (qc->by) {
        qcol = query_column(POST, (QryFld)qc->by);
        if (qc->lower)
            rc += sprintf(sql + rc, " AND %s >= :lower", qcol);
        if (qc->upper)
            rc += sprintf(sql + rc, " AND %s <= :upper", qcol);
        rc += sprintf(sql + rc, " ORDER BY %s %s", qcol, qc->by == ID ? "ASC" : "DESC");
    }
    if (qc->maxcnt)
        rc += sprintf(sql + rc, " LIMIT :maxcnt");

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return NULL;
    }

    rc = sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":uid"),
                            uid);
    rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":avail"),
                            POST_AVAILABLE);
    if (qc->lower) {
        rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":lower"),
                                qc->lower);
    }
    if (qc->upper) {
        rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":upper"),
                                qc->upper);
    }
    if (qc->maxcnt) {
        rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":maxcnt"),
                                qc->maxcnt);
    }
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter avail failed");
        sqlite3_finalize(stmt);
        return NULL;
    }

    it = it_create(stmt, row2likedpost);
    if (!it) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    return it;
}

static
void *row2likeddata(sqlite3_stmt *stmt)
{
    const char *proof = (const char *)sqlite3_column_text(stmt, 4);
    const char *name = (const char *)sqlite3_column_text(stmt, 5);
    const char *did = (const char *)sqlite3_column_text(stmt, 6);
    LikeInfo *li = (LikeInfo *)rc_zalloc(sizeof(LikeInfo) + strlen(proof) + 
            strlen(name) + strlen(did) + 3, NULL);
    void *buf;

    if (!li) {
        vlogE(TAG_DB "OOM");
        return NULL;
    }

    li->chan_id    = sqlite3_column_int64(stmt, 0);
    li->post_id    = sqlite3_column_int64(stmt, 1);
    li->cmt_id     = sqlite3_column_int64(stmt, 2);
    li->created_at = sqlite3_column_int64(stmt, 3);
    buf = li + 1;
    li->user.name    = strcpy((char *)buf, name);
    buf = (char *)buf + strlen(name) + 1;
    li->user.did     = strcpy((char *)buf, did);
    buf = (char *)buf + strlen(did) + 1;
    li->proof      = strcpy((char *)buf, proof);

    return li;
}

DBObjIt *db_iter_liked_data(uint64_t uid, const QryCriteria *qc)
{
    sqlite3_stmt *stmt;
    const char *qcol;
    char sql[1024] = {0};
    DBObjIt *it;
    int rc;

    rc = sprintf(sql,
          /*       "SELECT channel_id, post_id, comment_id, created_at, proof "
                 "  FROM (SELECT user_id FROM users "
                 "          WHERE user_id = :uid) JOIN "
                 "          likes USING (user_id)"
                 "  WHERE status = :avail");*/
                 "SELECT channel_id, post_id, comment_id, created_at, proof, "
                 "  name, did FROM likes JOIN users USING (user_id) "
                 "  where user_id = :uid");
    if (qc->by) {
        qcol = query_column(POST, (QryFld)qc->by);
        if (qc->lower)
            rc += sprintf(sql + rc, " AND %s >= :lower", qcol);
        if (qc->upper)
            rc += sprintf(sql + rc, " AND %s <= :upper", qcol);
        rc += sprintf(sql + rc, " ORDER BY %s %s", qcol, qc->by == ID ? "ASC" : "DESC");
    }
    if (qc->maxcnt)
        rc += sprintf(sql + rc, " LIMIT :maxcnt");

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return NULL;
    }

    rc = sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":uid"),
                            uid);
    if (qc->lower) {
        rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":lower"),
                                qc->lower);
    }
    if (qc->upper) {
        rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":upper"),
                                qc->upper);
    }
    if (qc->maxcnt) {
        rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":maxcnt"),
                                qc->maxcnt);
    }
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter failed");
        sqlite3_finalize(stmt);
        return NULL;
    }

    it = it_create(stmt, row2likeddata);
    if (!it) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    return it;
}

static
void *row2cmt(sqlite3_stmt *stmt)
{
    CmtStat stat = (CmtStat)sqlite3_column_int64(stmt, 3);
    size_t content_len = stat == CMT_AVAILABLE ? sqlite3_column_int64(stmt, 8) : 0;
    size_t thu_len = stat == CMT_AVAILABLE ? sqlite3_column_int64(stmt, 15) : 0;
    const char *hash_id = (const char *)sqlite3_column_text(stmt, 12);  //2.0
    const char *proof = (const char *)sqlite3_column_text(stmt, 13);  //2.0
    const char *name = (const char *)sqlite3_column_text(stmt, 5);
    const char *did = (const char *)sqlite3_column_text(stmt, 6);
    CmtInfo *ci = (CmtInfo *)rc_zalloc(sizeof(CmtInfo) + content_len + thu_len +
                            strlen(hash_id) + strlen(proof) + strlen(name) +
                            strlen(did) + 6, NULL);
    void *buf;

    if (!ci) {
        vlogE(TAG_DB "OOM");
        return NULL;
    }

    ci->chan_id      = sqlite3_column_int64(stmt, 0);
    ci->post_id      = sqlite3_column_int64(stmt, 1);
    ci->cmt_id       = sqlite3_column_int64(stmt, 2);
    ci->stat         = stat;
    ci->reply_to_cmt = sqlite3_column_int64(stmt, 4);
    buf = ci + 1;
    ci->user.name    = strcpy((char *)buf, name);
    buf = (char *)buf + strlen(name) + 1;
    ci->user.did     = strcpy((char *)buf, did);
    buf = (char *)buf + strlen(did) + 1;
    ci->hash_id      = strcpy((char *)buf, hash_id);  //2.0
    buf = (char *)buf + strlen(hash_id) + 1;  //2.0
    ci->proof        = strcpy((char *)buf, proof);  //2.0
    if (stat == CMT_AVAILABLE) {
        buf = (char *)buf + strlen(proof) + 1;  //2.0
        ci->content  = memcpy(buf, sqlite3_column_blob(stmt, 7), content_len);
        ci->con_len  = content_len;
        buf = (char *)buf + content_len + 1;   //2.0
        ci->thumbnails = memcpy(buf, sqlite3_column_blob(stmt, 14), thu_len);  //2.0
        ci->thu_len = thu_len;  //2.0
    }
    ci->likes        = sqlite3_column_int64(stmt, 9);
    ci->created_at   = sqlite3_column_int64(stmt, 10);
    ci->upd_at       = sqlite3_column_int64(stmt, 11);

    return ci;
}

static
void *row2reportedcmt(sqlite3_stmt *stmt)
{
    const char *name = (const char *)sqlite3_column_text(stmt, 3);
    const char *did = (const char *)sqlite3_column_text(stmt, 4);
    const char *reasons = (const char *)sqlite3_column_text(stmt, 5);
    ReportedCmtInfo *rci = (ReportedCmtInfo *)rc_zalloc(sizeof(CmtInfo) +
                            strlen(name) + strlen(did) + strlen(reasons) + 3, NULL);
    void *buf;

    if (!rci) {
        vlogE(TAG_DB "OOM");
        return NULL;
    }

    buf = rci + 1;

    rci->chan_id      = sqlite3_column_int64(stmt, 0);
    rci->post_id      = sqlite3_column_int64(stmt, 1);
    rci->cmt_id       = sqlite3_column_int64(stmt, 2);
    rci->reporter.name    = strcpy((char *)buf, name);
    buf = (char *)buf + strlen(name) + 1;
    rci->reporter.did     = strcpy((char *)buf, did);
    buf = (char *)buf + strlen(did) + 1;
    rci->reasons     = strcpy((char *)buf, reasons);
    rci->created_at   = sqlite3_column_int64(stmt, 6);

    return rci;
}

DBObjIt *db_iter_cmts(uint64_t chan_id, uint64_t post_id, const QryCriteria *qc)
{
    sqlite3_stmt *stmt;
    const char *qcol;
    char sql[1024] = {0};
    DBObjIt *it;
    int rc;

    rc = sprintf(sql,
                 "SELECT channel_id, post_id, comment_id, status, refcomment_id, "
                 "       name, did, content, length(content), likes, created_at, "
                 "       updated_at, hash_id, proof, thumbnails, length(thumbnails) "
                 "  FROM comments JOIN users USING (user_id) "
                 "  WHERE channel_id = :channel_id AND post_id = :post_id");
    if (qc->by) {
        qcol = query_column(COMMENT, (QryFld)qc->by);
        if (qc->lower)
            rc += sprintf(sql + rc, " AND %s >= :lower", qcol);
        if (qc->upper)
            rc += sprintf(sql + rc, " AND %s <= :upper", qcol);
        rc += sprintf(sql + rc, " ORDER BY %s %s", qcol, qc->by == ID ? "ASC" : "DESC");
    }
    if (qc->maxcnt)
        rc += sprintf(sql + rc, " LIMIT :maxcnt");

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return NULL;
    }

    rc = sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":channel_id"),
                            chan_id);
    rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":post_id"),
                            post_id);
    if (qc->lower) {
        rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":lower"),
                                qc->lower);
    }
    if (qc->upper) {
        rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":upper"),
                                qc->upper);
    }
    if (qc->maxcnt) {
        rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":maxcnt"),
                                qc->maxcnt);
    }
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter post_id failed");
        sqlite3_finalize(stmt);
        return NULL;
    }

    it = it_create(stmt, row2cmt);
    if (!it) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    return it;
}

static
void *row2cmtlikes(sqlite3_stmt *stmt)
{
    CmtInfo *ci = (CmtInfo *)rc_zalloc(sizeof(CmtInfo), NULL);
    if (!ci) {
        vlogE(TAG_DB "OOM");
        return NULL;
    }

    ci->chan_id = sqlite3_column_int64(stmt, 0);
    ci->post_id = sqlite3_column_int64(stmt, 1);
    ci->cmt_id  = sqlite3_column_int64(stmt, 2);
    ci->likes   = sqlite3_column_int64(stmt, 3);

    return ci;
}

DBObjIt *db_iter_cmts_likes(uint64_t chan_id, uint64_t post_id, const QryCriteria *qc)
{
    sqlite3_stmt *stmt;
    const char *qcol;
    char sql[1024] = {0};
    DBObjIt *it;
    int rc;

    rc = sprintf(sql,
                 "SELECT channel_id, post_id, comment_id, likes"
                 "  FROM comments"
                 "  WHERE channel_id = :channel_id AND post_id = :post_id");
    if (qc->by) {
        qcol = query_column(COMMENT, (QryFld)qc->by);
        if (qc->lower)
            rc += sprintf(sql + rc, " AND %s >= :lower", qcol);
        if (qc->upper)
            rc += sprintf(sql + rc, " AND %s <= :upper", qcol);
        rc += sprintf(sql + rc, " ORDER BY %s %s", qcol, qc->by == ID ? "ASC" : "DESC");
    }
    if (qc->maxcnt)
        rc += sprintf(sql + rc, " LIMIT :maxcnt");

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return NULL;
    }

    rc = sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":channel_id"),
                            chan_id);

    rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":post_id"),
                            post_id);
    if (qc->lower) {
        rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":lower"),
                                qc->lower);
    }
    if (qc->upper) {
        rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":upper"),
                                qc->upper);
    }
    if (qc->maxcnt) {
        rc |= sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":maxcnt"),
                                qc->maxcnt);
    }
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter failed");
        sqlite3_finalize(stmt);
        return NULL;
    }

    it = it_create(stmt, row2cmtlikes);
    if (!it) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    return it;
}

int db_iter_nxt(DBObjIt *it, void **obj)
{
    int rc;

    rc = sqlite3_step(it->stmt);
    if (rc != SQLITE_ROW) {
        if (rc != SQLITE_DONE)
            vlogE(TAG_DB "sqlite3_step() failed");
        *obj = NULL;
        return rc == SQLITE_DONE ? 1 : -1;
    }

    *obj = it->cb(it->stmt);
    return *obj ? 0 : -1;
}

int db_is_suber(uint64_t uid, uint64_t chan_id)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "SELECT EXISTS("
          "  SELECT * "
          "  FROM subscriptions "
          "  WHERE user_id = :uid AND channel_id = :channel_id"
          ")";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":uid"),
                            uid);
    rc |= sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":channel_id"),
                            chan_id);
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    if (SQLITE_ROW != sqlite3_step(stmt)) {
        vlogE(TAG_DB "Executing SELECT failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    return rc;
}

void db_deinit()
{
    // sqlite3_close(db);
    // sqlite3_shutdown();
}

static
void dbuinfo_dtor(void *obj)
{
    DBUserInfo *ui = (DBUserInfo *)obj;

    if (ui->stmt)
        sqlite3_finalize(ui->stmt);
}

int db_get_owner(UserInfo **ui)
{
    sqlite3_stmt *stmt;
    const char *sql;
    DBUserInfo *tmp;
    int rc;

    sql = "SELECT did, name, email FROM users WHERE user_id = :owner_user_id";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_bind_int64(stmt,
                            sqlite3_bind_parameter_index(stmt, ":owner_user_id"),
                            OWNER_USER_ID);
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter owner_uiser_id failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (SQLITE_DONE  == rc) {
        sqlite3_finalize(stmt);
        *ui = NULL;
        return 0;
    }

    if (SQLITE_ROW != rc) {
        vlogE(TAG_DB "Executing SELECT failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    tmp = (DBUserInfo *)rc_zalloc(sizeof(DBUserInfo), dbuinfo_dtor);
    if (!tmp) {
        vlogE(TAG_DB "OOM");
        sqlite3_finalize(stmt);
        return -1;
    }

    tmp->info.uid   = OWNER_USER_ID;
    tmp->info.did   = (char *)sqlite3_column_text(stmt, 0);
    tmp->info.name  = (char *)sqlite3_column_text(stmt, 1);
    tmp->info.email = (char *)sqlite3_column_text(stmt, 2);
    tmp->stmt       = stmt;

    *ui = &tmp->info;

    return 0;
}

int db_need_upsert_user(const char *did)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "SELECT EXISTS(SELECT * FROM users WHERE did = :did AND name != 'NA')";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":did"),
                           did, -1, NULL);
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter did failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    if (SQLITE_ROW != sqlite3_step(stmt)) {
        vlogE(TAG_DB "Executing SELECT failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    return rc ? 0 : 1;
}

int db_get_user(const char *did, UserInfo **ui)
{
    sqlite3_stmt *stmt;
    const char *sql;
    DBUserInfo *tmp;
    int rc;

    sql = "SELECT user_id, did, name, email FROM users WHERE did = :did;";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_bind_text(stmt,
                           sqlite3_bind_parameter_index(stmt, ":did"),
                           did, -1, NULL);
    if (SQLITE_OK != rc) {
        vlogE(TAG_DB "Binding parameter did failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (SQLITE_DONE == rc) {
        sqlite3_finalize(stmt);
        *ui = NULL;
        return 0;
    }

    if (SQLITE_ROW != rc) {
        vlogE(TAG_DB "Executing SELECT failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    tmp = (DBUserInfo *)rc_zalloc(sizeof(DBUserInfo), dbuinfo_dtor);
    if (!tmp) {
        vlogE(TAG_DB "OOM");
        sqlite3_finalize(stmt);
        return -1;
    }

    tmp->info.uid   = sqlite3_column_int64(stmt, 0);
    tmp->info.did   = (char *)sqlite3_column_text(stmt, 1);
    tmp->info.name  = (char *)sqlite3_column_text(stmt, 2);
    tmp->info.email = (char *)sqlite3_column_text(stmt, 3);
    tmp->stmt       = stmt;

    *ui = &tmp->info;

    return 0;
}

int db_get_count(const char *table_name)
{
    sqlite3_stmt *stmt;
    char sql[128] = {0};
    int rc;

    snprintf(sql, sizeof(sql), "SELECT count(*) FROM %s", table_name);

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    if (SQLITE_ROW != sqlite3_step(stmt)) {
        vlogE(TAG_DB "Executing SELECT failed");
        sqlite3_finalize(stmt);
        return -1;
    }

    rc = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    return rc;
}

int db_add_reported_cmts(uint64_t channel_id, uint64_t post_id, uint64_t comment_id,
        uint64_t reporter_id, const char *reason)
{
    sqlite3_stmt *stmt;
    const char *sql;
    int rc;

    sql = "BEGIN";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "Exectuing BEGIN failed");
        return -1;
    }

    do {
        sql = "INSERT OR REPLACE INTO reported_comments (channel_id, post_id, comment_id, reporter_id, created_at, reasons) "
              "  VALUES (:channel_id, :post_id, :comment_id, :reporter_id, :created_at, :reasons)";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":channel_id"),
                channel_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":post_id"),
                post_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":comment_id"),
                comment_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":reporter_id"),
                reporter_id);
        rc |= sqlite3_bind_int64(stmt,
                sqlite3_bind_parameter_index(stmt, ":created_at"),
                time(NULL));
        rc |= sqlite3_bind_text(stmt,
                sqlite3_bind_parameter_index(stmt, ":reasons"),
                reason, -1, NULL);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter failed");
            sqlite3_finalize(stmt);
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing INSERT failed");
            break;
        }

        sql = "END";

        if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
            vlogE(TAG_DB "sqlite3_prepare_v2() failed");
            break;
        }

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (SQLITE_DONE != rc) {
            vlogE(TAG_DB "Executing END failed");
            break;
        }

        return 0;
    } while(0);

    sql = "ROLLBACK";

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (SQLITE_DONE != rc) {
        vlogE(TAG_DB "ROLLBACK failed");
    }

    return -1;
}

DBObjIt *db_iter_reported_cmts(const QryCriteria *qc)
{
    sqlite3_stmt *stmt;
    const char *qcol;
    char sql[1024] = {0};
    DBObjIt *it;
    int rc;

    rc = sprintf(sql,
                 "SELECT channel_id, post_id, comment_id, name, did, reasons, created_at"
                 " FROM reported_comments"
                 " JOIN users ON reported_comments.reporter_id = users.user_id"
                 " WHERE true");

    if (qc->by) {
        qcol = query_column(COMMENT, (QryFld)qc->by);
        if (qc->lower)
            rc += sprintf(sql + rc, " AND %s >= :lower", qcol);
        if (qc->upper)
            rc += sprintf(sql + rc, " AND %s <= :upper", qcol);
        rc += sprintf(sql + rc, " ORDER BY %s %s", qcol, qc->by == ID ? "ASC" : "DESC");
    }
    if (qc->maxcnt)
        rc += sprintf(sql + rc, " LIMIT :maxcnt");
    vlogD(TAG_DB "db_iter_reported_cmts() origin sql: %s", sql);

    if (SQLITE_OK != sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) {
        vlogE(TAG_DB "sqlite3_prepare_v2() failed");
        return NULL;
    }

    if (qc->lower) {
        rc = sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":lower"),
                                qc->lower);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter lower failed");
            sqlite3_finalize(stmt);
            return NULL;
        }
    }

    if (qc->upper) {
        rc = sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":upper"),
                                qc->upper);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter upper failed");
            sqlite3_finalize(stmt);
            return NULL;
        }
    }

    if (qc->maxcnt) {
        rc = sqlite3_bind_int64(stmt, sqlite3_bind_parameter_index(stmt, ":maxcnt"),
                                qc->maxcnt);
        if (SQLITE_OK != rc) {
            vlogE(TAG_DB "Binding parameter maxcnt failed");
            sqlite3_finalize(stmt);
            return NULL;
        }
    }

    // char* expanded_sql = sqlite3_expanded_sql(stmt);
    // vlogI(TAG_DB "db_iter_reported_cmts() expanded sql: %s", expanded_sql);
    // sqlite3_free(expanded_sql);

    it = it_create(stmt, row2reportedcmt);
    if (!it) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    return it;
}

