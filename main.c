#include "std_c.h"
#include <getopt.h>
#include "pac.h"
#include <sys/utsname.h>

int udx710 = 0; //RG500U
int uix8910 = 0; //EC200U
int uic8850 = 0; //EC800G
int uic8310 = 0; //EC200D
int q_erase_all = 0;
int erase_all_once = 0;
static uint32_t frame_sz = 0;

typedef struct {
    uint32_t cmd;
    const char *name;
} BSL_CMD_NAME_T;

#define bsl_cmd_item(type) {type, #type}
static const BSL_CMD_NAME_T bsl_cmd_name[] = {
    bsl_cmd_item(BSL_CMD_CONNECT),
    bsl_cmd_item(BSL_CMD_START_DATA),
    bsl_cmd_item(BSL_CMD_MIDST_DATA),
    bsl_cmd_item(BSL_CMD_END_DATA),
    bsl_cmd_item(BSL_CMD_EXEC_DATA),
    bsl_cmd_item(BSL_CMD_NORMAL_RESET),
    bsl_cmd_item(BSL_CMD_READ_FLASH),
    bsl_cmd_item(BSL_CMD_CHANGE_BAUD),
    bsl_cmd_item(BSL_CMD_ERASE_FLASH),
    bsl_cmd_item(BSL_CMD_REPARTITION),
    bsl_cmd_item(BSL_CMD_START_READ),
    bsl_cmd_item(BSL_CMD_READ_MIDST),
    bsl_cmd_item(BSL_CMD_END_READ),
    bsl_cmd_item(BSL_CMD_DISABLE_TRANSCODE),
    bsl_cmd_item(BSL_CMD_WRITE_APR_INFO),
    bsl_cmd_item(BSL_CMD_ENABLE_DEBUG_MODE),

    bsl_cmd_item(BSL_REP_ACK),
    bsl_cmd_item(BSL_REP_VER),
    bsl_cmd_item(BSL_REP_INVALID_CMD),
    bsl_cmd_item(BSL_REP_UNKNOW_CMD),
    bsl_cmd_item(BSL_REP_OPERATION_FAILED),
    bsl_cmd_item(BSL_REP_NOT_SUPPORT_BAUDRATE),
    bsl_cmd_item(BSL_REP_DOWN_NOT_START),
    bsl_cmd_item(BSL_REP_DOWN_MUTI_START),
    bsl_cmd_item(BSL_REP_DOWN_EARLY_END),
    bsl_cmd_item(BSL_REP_DOWN_DEST_ERROR),
    bsl_cmd_item(BSL_REP_DOWN_SIZE_ERROR),
    bsl_cmd_item(BSL_REP_VERIFY_ERROR),
    bsl_cmd_item(BSL_REP_NOT_VERIFY),
    bsl_cmd_item(BSL_REP_READ_FLASH),
    bsl_cmd_item(BSL_REP_INCOMPATIBLE_PARTITION)
};

static int use_crc16BootCode = 0;
static size_t skip_7d = 0;
static int last_resp = 0;

extern int sendSync(int usbfd, const void *data, size_t len, int need_zlp){
    int rc;
    size_t olen = len;
    while(len > 0){
        if ((rc = write(usbfd, data, len)) < 0){
            if (errno == EAGAIN){
                usleep(1000);
                continue;
            }
            else{
                dprintf("write error: %d(%s)\r\n", rc, strerror(errno));
                break;
            }
        }
        len -= rc, data += rc;
    };
    // dprintf("write: %zu,%zu\r\n", olen, olen - len);
    usleep(5000);
    return rc;
}

extern int recvSync(int usbfd, void *data, size_t len, unsigned timeout){
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(usbfd, &rfds);

    struct timeval tv = {
        .tv_sec = timeout / 1000,
        .tv_usec = ((timeout % 1000) * 1000),
    };

    int rc = 0;
    select(usbfd + 1, &rfds, NULL, NULL, &tv);
    if(FD_ISSET(usbfd, &rfds)){
        rc = read(usbfd, data, len);
        if(rc < 0){
            dprintf("read error: %d(%s)\r\n", rc, strerror(errno));
        }
    }
    // dprintf("read: %zu,%d\r\n", len, rc);
    return rc;
}

#define KVERSION(j,n,p) ((j)*1000000 + (n)*1000 + (p))
static struct utsname utsname;  /* for the kernel version */
static int ql_get_kernel_version(void)
{
    int osmaj, osmin, ospatch;
    int kernel_version;

    uname(&utsname);
    osmaj = osmin = ospatch = 0;
    sscanf(utsname.release, "%d.%d.%d", &osmaj, &osmin, &ospatch);
    kernel_version = KVERSION(osmaj, osmin, ospatch);

    return kernel_version;
}

#define bsl_exec(_c) do{if (_c) {dprintf("failed: %s (%s: %s: %d)\n", #_c, __FILE__, __func__, __LINE__); return -1;}} while(0)

static PDL_CMD_T * pdl_cmd_reset(PDL_CMD_T *pdl_cmd, uint16_t cmd) {
    pdl_cmd->ucTag = 0xae;
    pdl_cmd->nDataSize= htole32(sizeof(struct pdl_pkt_tag));
    pdl_cmd->ucFlowID = 0xFF;
    pdl_cmd->wReserved = htole16(0);

    pdl_cmd->pkt[0].dwCmdType = htole32(cmd);
    pdl_cmd->pkt[0].dwDataAddr = htole32(0);
    pdl_cmd->pkt[0].dwDataSize = htole32(0);

    return pdl_cmd;
}

static int pdl_send_cmd(pac_ctx_t *ctx, PDL_CMD_T *pdl_cmd)
{
    int ret;

    ret = sendSync(ctx->usbfd, &pdl_cmd->ucTag, sizeof(PDL_CMD_T), 0);
    if (ret == sizeof(PDL_CMD_T)) {
        ret = sendSync(ctx->usbfd, pdl_cmd->pkt, sizeof(struct pdl_pkt_tag), 0);
        if (ret == sizeof(struct pdl_pkt_tag)) {
            int size = le32toh(pdl_cmd->nDataSize) - sizeof(struct pdl_pkt_tag);
            if (size > 0)
                ret = sendSync(ctx->usbfd, pdl_cmd->pkt[0].data, size, 0);
        }
    }

    return ret;
}

static PDL_CMD_T * pdl_read_cmd(pac_ctx_t *ctx, unsigned timeout)
{
    int ret;
    PDL_CMD_T *pdl_rsp = ctx->pdl_rsp;

    memset(pdl_rsp, 0, sizeof(PDL_CMD_T));
    ret = recvSync(ctx->usbfd, pdl_rsp, sizeof(ctx->bsl_rsp_data), timeout ? timeout : 15000);

    return (ret > 0) ? pdl_rsp : NULL;
}

int pdl_send_cmd_wait_ack(pac_ctx_t *ctx, PDL_CMD_T *pdl_req, uint16_t pdl_cmd, unsigned timeout) {
    int ret;
    PDL_CMD_T *pdl_rsp;

    if (!pdl_req) {
        pdl_req = pdl_cmd_reset(ctx->pdl_req, pdl_cmd);
    }

    ret = pdl_send_cmd(ctx, pdl_req);
    if (ret <= 0) return -1;

    pdl_rsp = pdl_read_cmd(ctx, timeout);
    if (pdl_rsp == NULL) return -1;

    if (le16toh(pdl_rsp->pkt[0].dwCmdType) != PDL_RSP_ACK)
        return -1;

    return 0;
}

static int pdl_flash_id(pac_ctx_t *ctx, Scheme_t *File) {
    int ret;
    size_t curSize = 0, fileSize;
    PDL_CMD_T *pdl_req = ctx->pdl_req;
    int index = 0;
    uint8_t end_flag[] = {0x1c, 0x3c, 0x6e, 0x06};

    dprintf("%-8s %s\n",  "Flash", File->FileID);

    bsl_exec(pac_open_bin(ctx, File->image));
    fileSize = File->image->dwLoFileSize;

    pdl_cmd_reset(pdl_req, PDL_CMD_START_DATA);
    pdl_req->pkt[0].dwDataAddr = htole32(strtoul(File->Base, NULL, 16));
    pdl_req->pkt[0].dwDataSize = htole32(fileSize);
    memcpy(pdl_req->pkt[0].data, "PDL1", 5);
    pdl_req->nDataSize= htole32(sizeof(struct pdl_pkt_tag) + 5);

    bsl_exec(pdl_send_cmd_wait_ack(ctx, pdl_req, 0, 1000));

    curSize = 0;
    while (curSize < fileSize)
    {
        ret = pac_read_bin(ctx, pdl_req->pkt[0].data, frame_sz);
        bsl_exec(ret <= 0);
        pdl_cmd_reset(pdl_req, PDL_CMD_MID_DATA);
        pdl_req->nDataSize= htole32(sizeof(struct pdl_pkt_tag) + ret);
        pdl_req->pkt[0].dwDataAddr = htole32(index++);
        pdl_req->pkt[0].dwDataSize = htole32(ret);

        curSize += ret;
        bsl_exec(pdl_send_cmd_wait_ack(ctx, pdl_req, 0, 0));
    }

    pdl_cmd_reset(pdl_req, PDL_CMD_END_DATA);
    memcpy(pdl_req->pkt[0].data, end_flag, 4);
    pdl_req->nDataSize= htole32(sizeof(struct pdl_pkt_tag) + 4);
    bsl_exec(pdl_send_cmd_wait_ack(ctx, pdl_req, 0, 0));

    return 0;
}

static BSL_CMD_T * bsl_cmd_reset(BSL_CMD_T * bsl_cmd, uint16_t cmd) {
    bsl_cmd->magic = 0x7e;
    bsl_cmd->cmd = htobe16(cmd);
    bsl_cmd->len = htobe16(0);

    return bsl_cmd;
}

void bsl_cmd_dump(BSL_CMD_T * bsl_cmd) {
    const char *name = NULL;
    uint16_t cmd = be16toh(bsl_cmd->cmd);
    size_t i;

    for (i = 0; i < (sizeof(bsl_cmd_name)/sizeof(bsl_cmd_name[0])); i++)
    {
        if (cmd == bsl_cmd_name[i].cmd) {
            name = bsl_cmd_name[i].name;
            break;
        }
    }

    if (!name) {
        dprintf("unknow bsl_cmd: cmd=%04x, len=%d\n", cmd, be16toh(bsl_cmd->len));
        return;
    }

    dprintf("\t%c %s\n", (cmd&0x80) ? '<' : '>', name);
}

void bsl_cmd_add_be32(BSL_CMD_T * bsl_cmd, uint32_t value) {
    size_t bsl_len = be16toh(bsl_cmd->len);

    *((uint32_t *)(&bsl_cmd->data[bsl_len])) = htobe32(value);
    bsl_cmd->len = htobe16(bsl_len + 4);
}

void bsl_cmd_add_le32(BSL_CMD_T * bsl_cmd, uint32_t value) {
    size_t bsl_len = be16toh(bsl_cmd->len);

    *((uint32_t *)&bsl_cmd->data[bsl_len]) = htole32(value);
    bsl_cmd->len = htobe16(bsl_len + 4);
}

void bsl_cmd_add_array(BSL_CMD_T * bsl_cmd, uint8_t *pBuf, size_t size) {
    size_t bsl_len = be16toh(bsl_cmd->len);

    memcpy(&bsl_cmd->data[bsl_len], pBuf, size);
    bsl_cmd->len = htobe16(bsl_len + size);
}

void bsl_cmd_add_partition(BSL_CMD_T * bsl_cmd, const char*pStr) {
    char str[0x48];
    size_t size =  strlen(pStr);
    size_t i;

    for (i = 0; i < size; i++) {
        str[i*2 + 0] = pStr[i];
        str[i*2 + 1] = 0;
    }
    for (i = size*2; i < sizeof(str); i++) {
        str[i] = 0;
    }

    bsl_cmd_add_array(bsl_cmd, (uint8_t *)str, sizeof(str));
}

void bsl_cmd_add_crc16(BSL_CMD_T * bsl_cmd, int BootCode) {
    uint8_t *src = &bsl_cmd->magic + 1;
    size_t len = be16toh(bsl_cmd->len);
    uint16_t crc = BootCode ? crc16BootCode(src, len + 4) : crc16FDL((uint16_t *)src, len + 4);

    *((uint16_t *)&bsl_cmd->data[len]) = htobe16(crc);
}

static int bsl_send_cmd(pac_ctx_t *ctx, BSL_CMD_T *bsl_cmd)
{
    uint8_t *buf = ctx->data_7e;
    size_t i, size = 0;
    size_t total = be16toh(bsl_cmd->len) + 2; //add crc16
    uint16_t req_cmd =  be16toh(bsl_cmd->cmd);

    if (req_cmd == BSL_CMD_READ_MIDST
         || req_cmd == BSL_CMD_MIDST_DATA
         || req_cmd == BSL_CMD_READ_FLASH)
        ;
    else
        bsl_cmd_dump(bsl_cmd);

    if (be16toh(bsl_cmd->len) && skip_7d) {
        bsl_cmd->data[total++] = 0x7e;
        size = 5 + total;

        return sendSync(ctx->usbfd, &bsl_cmd->magic, size, 1);
     }

    memcpy(buf + size, bsl_cmd, 5);
    size += 5;

    for (i = 0; i < total; i++) {
        uint8_t ch = bsl_cmd->data[i];

        if (ch == 0x7E || ch == 0x7D) {
            buf[size++] = 0x7D;
            buf[size++] = (0x20 ^ ch);
        } else {
            buf[size++] = ch;
        }
    }

    buf[size++] = 0x7e;

    return sendSync(ctx->usbfd, buf, size, 1);
}

static BSL_CMD_T * bsl_read_cmd(pac_ctx_t *ctx, unsigned timeout)
{
    int ret;
    BSL_CMD_T *bsl_rsp = ctx->bsl_rsp;

    memset(bsl_rsp, 0, sizeof(BSL_CMD_T));
    ret = recvSync(ctx->usbfd, bsl_rsp, sizeof(ctx->bsl_rsp_data), timeout ? timeout : 15000);

    if (ret > 0) {
        uint16_t req_cmd =  be16toh(ctx->bsl_req[0].cmd);
        uint16_t rsp_cmd =  be16toh(ctx->bsl_rsp[0].cmd);

        if ((req_cmd == BSL_CMD_READ_MIDST && rsp_cmd == BSL_REP_READ_FLASH)
            || (req_cmd == BSL_CMD_MIDST_DATA && rsp_cmd == BSL_REP_ACK)
            || (req_cmd == BSL_CMD_READ_FLASH && rsp_cmd == BSL_REP_READ_FLASH)
            || (rsp_cmd == BSL_REP_ACK))
            ;
        else
            bsl_cmd_dump(bsl_rsp);

        if (be16toh(bsl_rsp->cmd) == BSL_REP_READ_FLASH) {
            uint32_t need_len = (be16toh(bsl_rsp->len) + 1 + 2 + 2 + 2 + 1);
            uint32_t read_len = ret;

            if ((uix8910 || uic8850 || uic8310) && (skip_7d == 0)) {
                    uint8_t *data = (uint8_t *)bsl_rsp;
                    uint32_t i, cnt_7d = 0;

                    for (i = 0; i < ret; i++) {
                        if (data[i] == 0x7d) cnt_7d++;
                    }

                    while ((read_len < (need_len + cnt_7d)) /*&& (ret == 128 || ret == 129)*/) {
                        ret = recvSync(ctx->usbfd, data + read_len, sizeof(ctx->bsl_rsp_data), 1000);
                        if (ret > 0) {
                            for (i = 0; i < ret; i++) {
                                if (data[read_len+ i] == 0x7d) cnt_7d++;
                            }
                            read_len += ret;
                        }
                        else {
                            return NULL;
                        }
                    }

                    if (data[0] != 0x7e) {
                      dprintf("%s not start with 0x7e\n", __func__);
                      return NULL;
                    }
                    if (data[read_len - 1] != 0x7e) {
                      dprintf("%s not end with 0x7e\n", __func__);
                      return NULL;
                    }

                    cnt_7d = 1;
                    for (i = cnt_7d; i < (read_len - 1); i++) {
                        if (data[i] == 0x7d) {
                            i++;
                            data[cnt_7d++] = data[i] ^ 0x20;
                        }
                        else {
                            data[cnt_7d++] = data[i];
                        }
                    }
                    data[cnt_7d++] = data[read_len - 1];

                    if (read_len != cnt_7d) {
                        //printf("cnt_7d = %d\n", (read_len - cnt_7d));
                        read_len = cnt_7d;
                    }

                    if (need_len != read_len) {
                        dprintf("read: %d / need: %d\n", read_len, need_len);
                        return NULL;
                    }

                    if (skip_7d == 0) {
                        uint16_t crc16_1 = crc16FDL((uint16_t *)(&bsl_rsp->magic + 1), be16toh(bsl_rsp->len) + 4);
                        uint16_t crc16_2 =  be16toh(*((uint16_t *)(&(bsl_rsp->data[be16toh(bsl_rsp->len)]))));
                        if (crc16_1 != crc16_2) {
                            dprintf("%s crc16 un-match!\n", __func__);
                            return NULL;
                         }
                    }
            }

            if (need_len != read_len)
                dprintf("read: %d / need: %d\n", read_len, need_len);
        }
    }

    return (ret > 0) ? bsl_rsp : NULL;
}

int bsl_send_cmd_wait_ack(pac_ctx_t *ctx, BSL_CMD_T *bsl_req, uint16_t bsl_cmd, unsigned timeout) {
    int ret;
    BSL_CMD_T *bsl_rsp;

    if (!bsl_req) {
        bsl_req = bsl_cmd_reset(ctx->bsl_req, bsl_cmd);
        bsl_cmd_add_crc16(bsl_req, use_crc16BootCode);
    }

    ret = bsl_send_cmd(ctx, bsl_req);
    if (ret <= 0) return -1;

    bsl_rsp = bsl_read_cmd(ctx, timeout);
    if (bsl_rsp == NULL) return -1;

    last_resp = be16toh(bsl_rsp->cmd);

    if (last_resp != BSL_REP_ACK && last_resp != BSL_REP_DOWN_EARLY_END && be16toh(bsl_rsp->cmd) != BSL_REP_INCOMPATIBLE_PARTITION)
        return -1;

    return 0;
}

static int bsl_check_baud(pac_ctx_t *ctx) {
    int ret;
    uint8_t hello = BSL_CMD_CHECK_BAUD;
    int i;
    BSL_CMD_T *bsl_rsp;

    dprintf("\t%c %s\n", '>', "BSL_CMD_CHECK_BAUD");
    for (i = 0; i < 5; i++) {
        ret = sendSync(ctx->usbfd, &hello, 1, 0);
        if (ret != 1) return -1;

        bsl_rsp = bsl_read_cmd(ctx, 1000);
        if (bsl_rsp && be16toh(bsl_rsp->cmd) == BSL_REP_VER)
            return 0;
    }

    return -1;
}

static int bsl_change_baud(pac_ctx_t *ctx) {
    BSL_CMD_T *bsl_req = ctx->bsl_req;

    bsl_cmd_reset(bsl_req, BSL_CMD_CHANGE_BAUD);
    bsl_cmd_add_be32(bsl_req, 115200);
    bsl_cmd_add_crc16(bsl_req, 0);
    bsl_exec(bsl_send_cmd_wait_ack(ctx, bsl_req, 0, 0));

    return 0;
}


static int FileisNV(Scheme_t *File) {
    if (uix8910 || uic8850)
        return (!strcasecmp(File->FileID, "NV"));
    else if (uic8310)
        return (!strcasecmp(File->FileID, "NV"));

    return (!strcasecmp(File->FileID, "NV_NR"));
}

static int bsl_flash_id(pac_ctx_t *ctx, Scheme_t *File) {
    int ret;
    size_t curSize = 0, fileSize;
    BSL_CMD_T *bsl_req = ctx->bsl_req;
    const char *base = NULL;
    uint32_t crc32 = 0;
    uint16_t crc16 = 0;
    int nv_crc = FileisNV(File);

    dprintf("%-8s %s\n",  "Flash", File->FileID);

#if 0 //for reduce test time
    if (!strcasecmp(File->FileID, "AP") || !strcasecmp(File->FileID, "PS"))
        return 0;
#endif

    if (uic8850 && !strcasecmp(File->FileID, "NV"))
        frame_sz = FRAMESZ_PDL;

    if (uic8310 && !strcasecmp(File->FileID, "NV"))
        frame_sz = FRAMESZ_PDL;

    bsl_cmd_reset(bsl_req, BSL_CMD_START_DATA);

    base = File->Block[0] ? File->Block : File->Base;
    fileSize = File->image->dwLoFileSize;
    if (nv_crc && File->nv_buf) {
        fileSize = File->nv_size;
    } else if (File->backup_fp) {
        if (udx710 == 1 && File->CheckFlag[0] == '0')
        {
            //解决展锐RG500U-CNAB新版本升级出错问题
        }else
        {
            bsl_exec(fseek(File->backup_fp, 0, SEEK_END));
            fileSize = ftell(File->backup_fp);
        }
        bsl_exec(fseek(File->backup_fp, 0, SEEK_SET));
    }
    else {
        bsl_exec(pac_open_bin(ctx, File->image));
    }

    if (!strncasecmp(base, "0x", 2)) {
        bsl_cmd_add_be32(bsl_req, strtoul(base, NULL, 16));
        bsl_cmd_add_be32(bsl_req, fileSize);
    }
    else {
        bsl_cmd_add_partition(bsl_req, base);
        bsl_cmd_add_le32(bsl_req, fileSize);
     }

    if (nv_crc) {
        if (File->nv_buf)
            nv_checksum_buf(File->nv_buf, File->nv_size, &crc32, &crc16);
        else {
            nv_checksum_file(ctx->pac_fp, fileSize, &crc32, &crc16);
            fseek(ctx->pac_fp, File->image->dwLoDataOffset, SEEK_SET);
        }

        if (!strncasecmp(base, "0x", 2))
            bsl_cmd_add_be32(bsl_req, crc32);
        else
            bsl_cmd_add_le32(bsl_req, crc32);
    }

    bsl_cmd_add_crc16(bsl_req, use_crc16BootCode);
    bsl_exec(bsl_send_cmd_wait_ack(ctx, bsl_req, 0, 0));

    dprintf("\t%c", '>');

    curSize = 0;
    while (curSize < fileSize)
    {
        bsl_cmd_reset(bsl_req, BSL_CMD_MIDST_DATA);
        if (nv_crc && File->nv_buf) {
            ret = fileSize - curSize;
            if (ret > frame_sz)
                ret = frame_sz;
            memcpy(bsl_req->data,  File->nv_buf + curSize, ret);
        }
        else if (File->backup_fp) {
            ret = fread(bsl_req->data, 1, frame_sz, File->backup_fp);
#if 0
            if (curSize == 0 && !strcmp(File->FileID, "PhaseCheck")) {
                const char *sn = "D1Q21A8210000391P"; //AT+EGMR=0,5

                if (udx710) {
                    memset(bsl_req->data, 0xFF, 0x100);
                    memcpy(bsl_req->data, sn, strlen(sn));                   
                }
                else if (uix8910) {
                    typedef struct _tagSP09_PHASE_CHECK
                    {
                        char Magic[4];   /*90PS*/             // "SP09"   (老接口为SP05)
                        char    SN1[24];       // SN , SN_LEN=24
                        char    SN2[24];       // add for Mobile
                        int     StationNum;                 // the test station number of the testing
                    } SP09_PHASE_CHECK_T;
                    memset(((SP09_PHASE_CHECK_T *)(bsl_req->data))->SN1, 0, 24);
                    memcpy(((SP09_PHASE_CHECK_T *)(bsl_req->data))->SN1, sn, strlen(sn));                   
                }
            }
#endif
        }
        else {
            ret = pac_read_bin(ctx, bsl_req->data, frame_sz);
        }
        if (ret <= 0) break;
        if (nv_crc && (curSize == 0))
            *((uint16_t *)(bsl_req->data)) = htobe16(crc16);
    if ((ret&1) == 1)
        bsl_req->data[ret++] = 0;

        bsl_req->len = htobe16(ret);
        bsl_cmd_add_crc16(bsl_req, use_crc16BootCode);

        curSize += ret;
        cprintf("%c", '>');
        bsl_exec(bsl_send_cmd_wait_ack(ctx, bsl_req, 0, 0));
    }

    cprintf("\r\n");

    if (File->backup_fp) {
        fclose(File->backup_fp);
        File->backup_fp = NULL;
    }

    if (File->nv_buf) {
        free(File->nv_buf);
        File->nv_buf = NULL;
    }

    bsl_exec(bsl_send_cmd_wait_ack(ctx, NULL, BSL_CMD_END_DATA, 0));

    return 0;
}

static int bsl_backup_id(pac_ctx_t *ctx, Scheme_t *File) {
    size_t curSize = 0, fileSize;
    BSL_CMD_T *bsl_req = ctx->bsl_req;
    BSL_CMD_T *bsl_rsp;
    FILE *fp = NULL;
    char *backup_dir = "/tmp";
    char backup_file[256];
    int nv_crc = FileisNV(File);

    if (access(backup_dir, W_OK) && errno == ENOENT)
        backup_dir = "/data";
    if (access(backup_dir, W_OK) && errno == ENOENT)
        backup_dir = "/cache";
    snprintf(backup_file, sizeof(backup_file), "%s/quectel_back_%s", backup_dir, File->FileID);
    dprintf("%-8s %s -> '%s'\n", "Backup", File->FileID, backup_file);

    fileSize = strtoul(File->Size, NULL, 16);

    if (udx710) {
        bsl_cmd_reset(bsl_req, BSL_CMD_START_READ);
        bsl_cmd_add_partition(bsl_req, File->Block);
        bsl_cmd_add_le32(bsl_req, fileSize);
        bsl_cmd_add_crc16(bsl_req, 0);
        bsl_exec(bsl_send_cmd_wait_ack(ctx, bsl_req, 0, 0));
    }

    curSize = 0;
    while (curSize < fileSize)
    {
        if (uix8910 || uic8850 || uic8310) {
            bsl_cmd_reset(bsl_req, BSL_CMD_READ_FLASH);
            bsl_cmd_add_be32(bsl_req, strtoul(File->Base, NULL, 16));
            if (uix8910 || uic8850 || uic8310)
                bsl_cmd_add_be32(bsl_req, min(FRAMESZ_DATA, fileSize - curSize));

            bsl_cmd_add_be32(bsl_req, curSize);
            bsl_cmd_add_crc16(bsl_req, 0);
        }
        else {
            bsl_cmd_reset(bsl_req, BSL_CMD_READ_MIDST);
            bsl_cmd_add_le32(bsl_req, min(FRAMESZ_DATA, fileSize - curSize));
            bsl_cmd_add_le32(bsl_req, curSize);
            bsl_cmd_add_crc16(bsl_req, 0);
        }

        bsl_exec(bsl_send_cmd(ctx, bsl_req) < 1);

        bsl_rsp = bsl_read_cmd(ctx, 0);
        bsl_exec(bsl_rsp == NULL);

        if (be16toh(bsl_rsp->cmd) != BSL_REP_READ_FLASH)
            return -1;

        if (curSize == 0) {
            fp = fopen(backup_file, "wb");
            if (fp == NULL) {
                printf("fopen %s, errno: %d (%s)\n", backup_file, errno, strerror(errno));
                return -1;
            }

            if (nv_crc) {
                uint32_t tmp = nv_get_size(bsl_rsp->data, be16toh(bsl_rsp->len));
                if (tmp && tmp < fileSize) fileSize = tmp;
            }
        }

        if (fwrite(bsl_rsp->data, 1, be16toh(bsl_rsp->len), fp) != be16toh(bsl_rsp->len)) {
            dprintf("faill to save %zd bytes\n", File->nv_size);
            fclose(fp);
            return -1;
        }

        curSize += be16toh(bsl_rsp->len);
    }

    fclose(fp);
    if (nv_crc) {
        bsl_exec(pac_open_bin(ctx, File->image));
        File->nv_size = File->image->dwLoFileSize; //fileSize; //fix by neil, when old nv file's size < new nv file's size, we should use new nv file's size
        File->nv_buf = malloc(File->nv_size);
        if (!File->nv_buf) {
            dprintf("faill to malloc %zd bytes\n", File->nv_size);
            return -1;
        }
        pac_read_bin(ctx, File->nv_buf, File->nv_size);

        bsl_exec(nv_merg_file(backup_file, File->nv_buf, File->nv_size, ctx->NVBackupList, ctx->NVBackupNum));
        #if 0
        {
            FILE *save_nv = fopen("/tmp/NV_NR", "wb");
            if (save_nv) {
                fwrite(File->nv_buf, 1, File->nv_size, save_nv);
                fclose(save_nv);
            }
        }
        #endif
    }
    else {
        File->backup_fp = fopen(backup_file, "rb");
    }

    if (udx710)
        bsl_exec(bsl_send_cmd_wait_ack(ctx, NULL, BSL_CMD_END_READ, 0));

    return 0;
}

static int bsl_erase_id(pac_ctx_t *ctx, Scheme_t *File) {
    BSL_CMD_T *bsl_req = ctx->bsl_req;

    dprintf("%-8s %s\n", "Erase", File->FileID);
    bsl_cmd_reset(bsl_req, BSL_CMD_ERASE_FLASH);
    if (File->Block[0]) {
        bsl_cmd_add_partition(bsl_req, File->Block);
        bsl_cmd_add_le32(bsl_req, 0);
    }
    else {
        bsl_cmd_add_be32(bsl_req, strtoul(File->Base, NULL, 16));
        bsl_cmd_add_be32(bsl_req, strtoul(File->Size, NULL, 16));
    }
    bsl_cmd_add_crc16(bsl_req, 0);

    if (q_erase_all)
        bsl_exec(bsl_send_cmd_wait_ack(ctx, bsl_req, 0, 30000));  //erase all need at least 22 seconds
    else
        bsl_exec(bsl_send_cmd_wait_ack(ctx, bsl_req, 0, 0));

    return 0;
}

static int bsl_re_parttition(pac_ctx_t *ctx) {
    BSL_CMD_T *bsl_req = ctx->bsl_req;
    unsigned i;

    bsl_cmd_reset(bsl_req, BSL_CMD_REPARTITION);
    for (i = 0; i < ctx->PartitionNum; i++) {
        uint32_t psz =  ctx->PartitionList[i].PartitionSize;
        if (psz != 0xFFFFFFFF)
           psz = psz / 1024 / 1024;
        bsl_cmd_add_partition(bsl_req,  ctx->PartitionList[i].id);
        bsl_cmd_add_le32(bsl_req, psz);
    }
    bsl_cmd_add_crc16(bsl_req, 0);

    bsl_exec(bsl_send_cmd_wait_ack(ctx, bsl_req, 0, 0));

     return 0;
}

static int  test_bsl(pac_ctx_t *ctx ) {
    unsigned i, j;

    for (i = 0; i < ctx->SchemeNum; i++)
    {
        Scheme_t *x = &ctx->SchemeList[i];
        Scheme_t *bx;

        if (q_erase_all && uix8910 && erase_all_once)    //erass all
        {
            Scheme_t x_tmp;
            memset(&x_tmp, 0, sizeof(Scheme_t));
            snprintf(x_tmp.Base, sizeof(x->Base), "0x%08x", 0x00000000);
            snprintf(x_tmp.Size, sizeof(x->Base), "0x%08x", 0xffffffff);

            bsl_exec(bsl_erase_id(ctx, &x_tmp));
            bsl_exec(bsl_send_cmd_wait_ack(ctx, NULL, BSL_CMD_REPARTITION, 0));
            erase_all_once = 0;
        }

        if (!strcasecmp(x->FileID, "HOST_FDL")) {
            frame_sz = FRAMESZ_PDL;
            pdl_send_cmd_wait_ack(ctx, NULL, PDL_CMD_CONNECT, 1000);
            bsl_exec(pdl_flash_id(ctx, x));
            pdl_send_cmd_wait_ack(ctx, NULL, PDL_CMD_EXEC_DATA, 1000);
        }
        else if (!strcasecmp(x->FileID, "FDL")) {
            use_crc16BootCode = 1;
            frame_sz = FRAMESZ_BOOTCODE;
            bsl_exec(bsl_check_baud(ctx));
            bsl_exec(bsl_send_cmd_wait_ack(ctx, NULL, BSL_CMD_CONNECT, 0));
            bsl_exec(bsl_flash_id(ctx, x));
            bsl_exec(bsl_send_cmd_wait_ack(ctx, NULL, BSL_CMD_EXEC_DATA, 0));
            use_crc16BootCode = 0;

            if (uic8850)
            {
                int tmp = ql_get_kernel_version();
                if (tmp <= KVERSION(3,2,102))
                    frame_sz = 0x3c00;
                else
                    frame_sz = FRAMESZ_OUT_DATA;
            }
        }
        else if (!strcasecmp(x->FileID, "FDL2")) {
            erase_all_once = 1;
            frame_sz = FRAMESZ_FDL;
            bsl_exec(bsl_check_baud(ctx));
            bsl_exec(bsl_send_cmd_wait_ack(ctx, NULL, BSL_CMD_CONNECT, 0));
            if (uix8910)
                bsl_exec(bsl_change_baud(ctx));
            bsl_exec(bsl_flash_id(ctx, x));
            bsl_exec(bsl_send_cmd_wait_ack(ctx, NULL, BSL_CMD_EXEC_DATA, 0));
            if (udx710) {
                bsl_exec(bsl_send_cmd_wait_ack(ctx, NULL, BSL_CMD_DISABLE_TRANSCODE, 0));
                skip_7d = 1;
            }

            if (uix8910)
            frame_sz = FRAMESZ_PDL;
            else
            {
                int tmp = ql_get_kernel_version();
                if (tmp <= KVERSION(3,2,102))
                    frame_sz = 0x3c00;
                else
                    frame_sz = FRAMESZ_OUT_DATA;
            }

            for (j = i; j < ctx->SchemeNum; j++) {
                bx = &ctx->SchemeList[j];

                if (uix8910 || uic8310) {
                    if (!strcasecmp(bx->FileID, "NV") && !q_erase_all) {
                        bx->backup[0] = '1';
                    }
                }

                //bx->backup[0] = '0';
                if (bx->backup[0] == '1')
                    bsl_exec(bsl_backup_id(ctx, bx));
            }

            #if 0
            if (udx710)
                bsl_exec(bsl_re_parttition(ctx));

            if (udx710 == 1)
            {
                for (j--; j > i; j--) {
                    bx  = &ctx->SchemeList[j];
                    if (bx->backup[0] == '1')
                        bsl_exec(bsl_flash_id(ctx, bx));
                }
            }
            #endif
        }
        else if (x->backup[0] == '1' && udx710 == 1) {
        }
        else if (x->CheckFlag[0] == '0' && udx710 == 1) {
            dprintf("skip download FileID: %s\n", x->FileID);
        }
        else if (uic8310 && strncmp(x->FileID,"Erase BOOT0",11) == 0) {
            dprintf("into FileID: %s\n", x->FileID);
            bsl_exec(bsl_erase_id(ctx, x));
        }
        else if (uix8910 && (strcmp(x->FileID,"ERASE_BOOT") == 0 || strcmp(x->FileID,"ERASE_PY_FS_U") == 0
            || strcmp(x->FileID,"ERASE_PY_FS_B") == 0)) {
            bsl_exec(bsl_erase_id(ctx, x));
        }
        else if (uic8850 && strcmp(x->FileID,"ERASE_SPL") == 0)
        {
            bsl_exec(bsl_check_baud(ctx));
            bsl_exec(bsl_send_cmd_wait_ack(ctx, NULL, BSL_CMD_CONNECT, 0));
            bsl_exec(bsl_erase_id(ctx, x));

            for (j = i; j < ctx->SchemeNum; j++) {
                bx = &ctx->SchemeList[j];

                if (uic8850) {
                    if (!strcasecmp(bx->FileID, "NV") && !q_erase_all) {
                        bx->backup[0] = '1';   //default is 0
                    }
                }

                //bx->backup[0] = '0';
                if (bx->backup[0] == '1')
                    bsl_exec(bsl_backup_id(ctx, bx));
            }
        }
        else if (uic8850 && (!strcasecmp(x->FileID, "BOOT") || !strcasecmp(x->FileID, "PhaseCheck")
              || !strcasecmp(x->FileID, "FMT_FSEXT") || !strcasecmp(x->FileID, "FMT_FSSYS"))) {
            dprintf("skip FileID: %s\n", x->FileID);
        }
        else if (uic8310 && (!strcasecmp(x->FileID, "BOOT") || !strcasecmp(x->FileID, "EraseUserNV") || !strcasecmp(x->FileID, "EraseRunNV"))) {
            bsl_exec(bsl_erase_id(ctx, x));
        }
        else if (uic8310 && (!strcasecmp(x->FileID, "XFILE") || !strcasecmp(x->FileID, "AUTOSMS")
            || !strcasecmp(x->FileID, "OmadmFota") || !strcasecmp(x->FileID, "Preload")
            || !strcasecmp(x->FileID, "GPS_GL") || !strcasecmp(x->FileID, "GPS_BD")
            || !strcasecmp(x->FileID, "GPS_FDL") || !strcasecmp(x->FileID, "WCNCODE")
            || !strcasecmp(x->FileID, "RomDisk") || !strcasecmp(x->FileID, "APN")
            || !strncmp(x->FileID, "ERASE HIDDEN_DISK_C", 19) || !strncmp(x->FileID, "Erase QUEC_NV", 13)
            || !strcasecmp(x->FileID, "PhaseCheck") || !strcasecmp(x->FileID, "PreloadUdisk")
            || !strncmp(x->FileID, "Erase FS", 8))) {
            dprintf("skip FileID: %s\n", x->FileID);
        }
        else if (uic8310 && !strcasecmp(x->FileID, "FotaUpdate")) {
            bsl_exec(bsl_flash_id(ctx, x));
        }
        else if (x->image && x->image->szFileName[0]) {
            bsl_exec(bsl_flash_id(ctx, x));
        }
        else if (uix8910 && !strcasecmp(x->FileID, "FMT_FSSYS")) {
            //dprintf("Unknow FileID: %s\n", x->FileID);
        }
        else if (uic8850 && (!strcasecmp(x->FileID, "FMT_FSMOD") || !strcasecmp(x->FileID, "FLASH"))) {
            bsl_exec(bsl_erase_id(ctx, x));
        }
        else if (uix8910 && !strcasecmp(x->FileID, "FMT_FSEXT")) {
            //dprintf("Unknow FileID: %s\n", x->FileID);
        }
        else if (!strcasecmp(x->Type, "EraseFlash2"))
        {
            bsl_exec(bsl_erase_id(ctx, x));

            #if 1
            if (udx710)
                bsl_exec(bsl_re_parttition(ctx));

            if (udx710 == 1)
            {
                int SchemeNum = ctx->SchemeNum;
                for (SchemeNum--; SchemeNum > i; SchemeNum--) {
                    bx  = &ctx->SchemeList[SchemeNum];
                    if (bx->backup[0] == '1')
                        bsl_exec(bsl_flash_id(ctx, bx));
                }
            }
            #endif
        }
        else {
            if (uix8910) {
                if (!strcasecmp(x->FileID, "PhaseCheck") && !strcasecmp(x->Type, "CODE")) {
               /*
            <File>
                <ID>PhaseCheck</ID>
                <IDAlias>PhaseCheck</IDAlias>
                <Type>CODE</Type>
                <Block>
                    <Base>0xfe000002</Base>
                    <Size>0x100</Size>
                </Block>
                <Flag>0</Flag>
                <CheckFlag>0</CheckFlag>
                <Description>Producting phases information section</Description>
            </File>
                 */
                     continue;
                }
                else if (!strcasecmp(x->FileID, "FLASH") && !strcasecmp(x->Type, "EraseFlash")) {
                    bsl_exec(bsl_erase_id(ctx, x));
                    continue;
                }
            }

            if (!uix8910)     //unisoc 8910 No longer check Unknow FileID
            {
                dprintf("Unknow FileID: %s\n", x->FileID);
                return -1;
            }
        }
    }

    if(last_resp != BSL_REP_DOWN_EARLY_END)
    bsl_exec(bsl_send_cmd_wait_ack(ctx, NULL, BSL_CMD_NORMAL_RESET, 0));

    return 0;
}

static pac_ctx_t g_pac_ctx;
int dloader_main(int usbfd, FILE *fw_fp)
{
    pac_ctx_t *ctx = &g_pac_ctx;
    int ret = -1;

    memset(ctx, 0, sizeof(pac_ctx_t));
    ctx->pdl_req = (PDL_CMD_T *)ctx->bsl_req;
    ctx->pdl_rsp = (PDL_CMD_T *)ctx->bsl_rsp;
    ctx->usbfd = usbfd;

    if (pac_parser(ctx, fw_fp)){
        dprintf("invalid firmware file\r\n");
        goto out;
    }

    #define CHK_NAME(x) strstr((char*)ctx->pac_hdr.szPrdName, x)
    #define CHK_VERSION(x) strstr((char*)ctx->pac_hdr.szPrdVersion, x)

    if(CHK_NAME("710") || CHK_VERSION("710")) udx710 = 1;
    else if(CHK_NAME("8910") || CHK_VERSION("8910")) uix8910 = 1;
    else if(CHK_NAME("8850") || CHK_VERSION("8850")) uic8850 = 1;
    else if(CHK_NAME("8310") || CHK_VERSION("8310")) uic8310 = 1;
    else{
        ret = -2;
        dprintf("invalid modem\r\n");
        goto out;
    }

    dprintf("udx710: %d, uix8910: %d, uic8850: %d, uic8310: %d\r\n", udx710, uix8910, uic8850, uic8310);

    ret = test_bsl(ctx);
out:
    if (ctx->xml_buf)
        free(ctx->xml_buf);

    return ret;
}

#ifndef NV_MAIN
#include <termios.h>

int verbose = 0;
FILE *log_fp = NULL;
char log_buf[1024];
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static int tty_open(const char* tty_path){
  int fd = open(tty_path, O_RDWR | O_NOCTTY | O_NONBLOCK);
  if(fd >= 0){
    struct termios settings;
    memset(&settings, 0, sizeof(settings));
    cfmakeraw(&settings);
    settings.c_cflag |= CREAD | CLOCAL;
    tcflush(fd, TCIOFLUSH);
    tcsetattr(fd, TCSANOW, &settings);
    tcflush(fd, TCIOFLUSH);
  }
  else dprintf("tty_path error: %s\r\n", strerror(errno));

  return fd;
}

const char *get_time(void) {
    static char str[64];
    static unsigned start = 0;
    unsigned now;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    now = (unsigned)ts.tv_sec*1000 + (unsigned)(ts.tv_nsec / 1000000);
    if (start == 0)
        start = now;

    now -= start;
    snprintf(str, sizeof(str), "[%03d:%03d]", now/1000, now%1000);

    return str;
}

int main(int argc, char *argv[]){
    log_fp = stdout;
    // log_fp = fopen("./dloader.log", "wb");
    if(argc < 3){
        dprintf("Invalid args\r\n");
        return -1;
    }
    const char* tty_path = argv[1], *firmware_path = argv[2];
    dprintf("tty_path: %s\r\n", tty_path);
    dprintf("firmware_path: %s\r\n", firmware_path);

    int fd;
    while((fd = tty_open(tty_path)) < 0) sleep(1);
    FILE* fw_fp = fopen(firmware_path, "rb");
    if(fw_fp){
        dloader_main(fd, fw_fp);
        fclose(fw_fp);
    }
    else dprintf("firmware_path err: %s\r\n", strerror(errno));
    close(fd);
    if(log_fp != stdout) fclose(log_fp);
}
#endif
