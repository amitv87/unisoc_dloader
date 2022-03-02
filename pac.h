#ifndef __PAC_INCLUDE__
#define __PAC_INCLUDE__
#define FRAMESZ_BOOTCODE 0x210 // frame size for bootcode
#define FRAMESZ_PDL 0x800      // frame size for PDL
#define FRAMESZ_FDL 0x840      // frame size for fdl1
#define FRAMESZ_DATA 0x3000    // frame size for others
#define FRAMESZ_OUT_DATA 0xfc00    // windows use this value

struct bin_header_t
{
    uint32_t _dwSize;             // size of this struct itself
    uint16_t szFileID[256];      // file ID,such as FDL,Fdl2,NV and etc.
    uint16_t szFileName[256];    // file name,in the packet bin file,it only stores file name
                                 // but after unpacketing, it stores the full path of bin file
    uint16_t szFileVersion[252]; // Reserved now; V1->V2 : 256*2 --> 252*2
    uint32_t _dwHiFileSize;       // hight file size
    uint32_t _dwHiDataOffset;     // hight file size
    uint32_t dwLoFileSize;       // file size
    uint32_t _nFileFlag;          // if "0", means that it need not a file, and
                                 // it is only an operation or a list of operations, such as file ID is "FLASH"
                                 // if "1", means that it need a file
    uint32_t _nCheckFlag;         // if "1", this file must be downloaded;
                                 // if "0", this file can not be downloaded;
    uint32_t dwLoDataOffset;     // the offset from the packet file header to this file data
    uint32_t _dwCanOmitFlag;      // if "1", this file can not be downloaded and not check it as "All files"
                                 //   in download and spupgrade tool.
    uint32_t _dwAddrNum;
    uint32_t dwAddr[5];
    uint32_t dwReserved[249]; // Reserved for future,not used now
};

struct pac_header_t
{
    uint16_t szVersion[22];     // packet struct version; V1->V2 : 24*2 -> 22*2
    uint32_t _dwHiSize;          // the whole packet hight size;
    uint32_t _dwLoSize;          // the whole packet low size;
    uint16_t szPrdName[256];    // product name
    uint16_t szPrdVersion[256]; // product version
    uint32_t nFileCount;        // the number of files that will be downloaded, the file may be an operation
    uint32_t _dwFileOffset;      // the offset from the packet file header to the array of FILE_T struct buffer
    uint32_t _dwMode;
    uint32_t _dwFlashType;
    uint32_t _dwNandStrategy;
    uint32_t _dwIsNvBackup;
    uint32_t _dwNandPageType;
    uint16_t szPrdAlias[100]; // product alias
    uint32_t _dwOmaDmProductFlag;
    uint32_t _dwIsOmaDM;
    uint32_t _dwIsPreload;
    uint32_t dwReserved[200];
    uint32_t _dwMagic;
    uint16_t _wCRC1;
    uint16_t _wCRC2;
};

typedef struct {
    char id[32];
    char size[16];
    uint32_t PartitionSize;
} Partition_t;

typedef struct {
//<!--  File-ID: Can not be changed,it is used by tools           -->
    char FileID[32];
//<!--  File-IDAlias: This is  for GUI display can be changed     -->
    char IDAlias[32];
//<!--  File-Type: MasterImage,means it will add BOOT_PARAM       -->
//<!--             and OS_INFO information to file                -->
    char Type[16];
    char Block[16];
    char Base[16];
    char Size[16];
//<!--  File-Flag: 0, means this file need not  input file path   -->
//<!--             1, means this file need input file path        -->
    char Flag[16];
//<!--  File-CheckFlag: 0, this file is optional                  -->
//<!--                  1, must select this file                  -->
//<!--                  2, means not check this file in pack      -->
    char CheckFlag[16];

    char backup[4];
    FILE *backup_fp;
    void *nv_buf;
    size_t nv_size;

    struct bin_header_t *image;
    Partition_t *partition;
    char PartitionBase[32];
    uint32_t PartitionSize;
} Scheme_t;

typedef enum
{
    BSL_CMD_CHECK_BAUD = 0x7e,
    BSL_CMD_CONNECT = 0x0,
    BSL_CMD_START_DATA = 0x1,
    BSL_CMD_MIDST_DATA = 0x2,
    BSL_CMD_END_DATA = 0x3,
    BSL_CMD_EXEC_DATA = 0x4,
    BSL_CMD_NORMAL_RESET = 0x5,
    BSL_CMD_READ_FLASH = 0x6,
    BSL_CMD_CHANGE_BAUD = 0x9,
    BSL_CMD_ERASE_FLASH = 0xa,
    BSL_CMD_REPARTITION = 0x0b,
    BSL_CMD_START_READ = 0x10,
    BSL_CMD_READ_MIDST = 0x11,
    BSL_CMD_END_READ = 0x12,
    BSL_CMD_EXEC_NAND_INIT = 0x21,
    BSL_CMD_DISABLE_TRANSCODE	= 0x21,		/* 0x21 Use the non-escape function */
    BSL_CMD_WRITE_APR_INFO		= 0x22,		/* 0x22 Write pac file build time to miscdata for APR */
    BSL_CMD_ENABLE_DEBUG_MODE	= 0x25,		/* 0x25 Enable debug mode */

    BSL_REP_ACK = 0x80,
    BSL_REP_VER = 0x81,
    BSL_REP_INVALID_CMD = 0x82,
    BSL_REP_UNKNOW_CMD = 0x83,
    BSL_REP_OPERATION_FAILED = 0x84,
    BSL_REP_NOT_SUPPORT_BAUDRATE = 0x85,
    BSL_REP_DOWN_NOT_START = 0x86,
    BSL_REP_DOWN_MUTI_START = 0x87,
    BSL_REP_DOWN_EARLY_END = 0x88,
    BSL_REP_DOWN_DEST_ERROR = 0x89,
    BSL_REP_DOWN_SIZE_ERROR = 0x8a,
    BSL_REP_VERIFY_ERROR = 0x8b,
    BSL_REP_NOT_VERIFY = 0x8c,
    BSL_REP_READ_FLASH = 0x93,
    BSL_REP_INCOMPATIBLE_PARTITION = 0x96,
} BSL_CMD_E;

typedef enum
{
    PDL_CMD_CONNECT,
    PDL_CMD_ERASE_FLASH,
    PDL_CMD_ERASE_PARTITION,
    PDL_CMD_ERASE_ALL,
    PDL_CMD_START_DATA,
    PDL_CMD_MID_DATA,
    PDL_CMD_END_DATA,
    PDL_CMD_EXEC_DATA,
    PDL_CMD_READ_FLASH,
    PDL_CMD_READ_PARTITIONS,
    PDL_CMD_NORMAL_RESET,
    PDL_CMD_READ_CHIPID,
    PDL_CMD_SET_BAUDRATE,
} PDLREQ;

typedef enum
{
    PDL_RSP_ACK,

    /// from PC command
    PDL_RSP_INVALID_CMD,
    PDL_RSP_UNKNOWN_CMD,
    PDL_RSP_INVALID_ADDR,
    PDL_RSP_INVALID_BAUDRATE,
    PDL_RSP_INVALD_PARTITION,
    PDL_RSP_SIZE_ERROR,
    PDL_RSP_WAIT_TIMEOUT,

    /// from phone
    PDL_RSP_VERIFY_ERROR,
    PDL_RSP_CHECKSUM_ERROR,
    PDL_RSP_OPERATION_FAILED,

    /// phone internal
    PDL_RSP_DEVICE_ERROR, //DDR,NAND init errors
    PDL_RSP_NO_MEMORY
} PDLREP;

typedef struct {
    uint8_t magic;
    uint16_t cmd;
    uint16_t len;
    uint8_t data[0];
} __attribute__ ((packed)) BSL_CMD_T;

// response only has field 'dwCmdType'
struct pdl_pkt_tag
{
    uint32_t dwCmdType;
    uint32_t dwDataAddr;
    uint32_t dwDataSize;
    uint8_t data[0];
} __attribute__ ((packed));

typedef struct pdl_pkt_header
{
    uint8_t ucTag;      //< 0xAE
    uint32_t nDataSize; //< data size
    uint8_t ucFlowID;   //< 0xFF
    uint16_t wReserved; //< reserved 0
    struct pdl_pkt_tag pkt[0];
} __attribute__ ((packed)) PDL_CMD_T;

typedef struct {
    int usbfd;
    FILE *pac_fp;
    struct pac_header_t pac_hdr;
    struct bin_header_t bin_hdr[64];
    int PartitionNum;
    Partition_t PartitionList[64];
    int SchemeNum;
    Scheme_t SchemeList[64];
    size_t cur_bin_offset;
    int NVBackupNum;
    uint16_t NVBackupList[1024];
    struct bin_header_t *cur_bin_hdr;
    char *xml_buf;
    size_t xml_len;

    BSL_CMD_T bsl_req[1];
    uint8_t bsl_req_data[FRAMESZ_OUT_DATA+32];
    BSL_CMD_T bsl_rsp[1];
    uint8_t bsl_rsp_data[16*1024];
    uint8_t data_7e[FRAMESZ_OUT_DATA+512];

    PDL_CMD_T *pdl_req;
    PDL_CMD_T *pdl_rsp;
} pac_ctx_t;

extern int pac_parser( pac_ctx_t *ctx, FILE *fw_fp);
extern struct bin_header_t * pac_lookup_FileName(pac_ctx_t *ctx, const char *FileName);
extern struct bin_header_t * pac_lookup_FileID(pac_ctx_t *ctx, const char *FileID);
extern int pac_open_bin(pac_ctx_t *ctx, struct bin_header_t *bin_hdr);
extern int pac_read_bin(pac_ctx_t *ctx, void *pBuf, size_t nSize);

extern size_t nv_get_size(uint8_t * lpCodeSrc, uint32_t dwCodeSizeSrc);
extern int nv_merg_file(const char *src_file, uint8_t *dst_p, size_t dst_size, uint16_t *back_list, size_t back_num);

extern uint16_t crc16NV(uint16_t crc, const uint8_t *buffer, uint32_t len);
extern uint16_t crc16FDL(const uint16_t *src, size_t len);
extern uint16_t crc16BootCode(uint8_t *src, size_t len);
extern void nv_checksum_buf(uint8_t *data, size_t size, uint32_t *crc32, uint16_t*crc16);
extern void nv_checksum_file(FILE *fp, size_t size, uint32_t *crc32, uint16_t*crc16);

extern char * xml_find_key_value(const char *xml_s, const char *xml_e, const char *key, size_t *pSize);
extern char * xml_find_node_header(const char *xml_s, const char *xml_e, const char *node, size_t *pSize);
extern char * xml_find_node_value(const char *xml_s, const char *xml_e, const char *node, size_t *pSize);
#endif
