#include "std_c.h"
#include "pac.h"
extern int udx710;

#define goto_out(x) do {if (x) {dprintf("failed: %s (%s: %s: %d)\n", #x, __FILE__, __func__, __LINE__);goto out; }} while (0);
const char *wcharToChar(uint16_t *pBuf, size_t nSize)
{
    size_t i;
    char *buf = (char *)pBuf;

    for (i = 0; i < (nSize/2) ; i++) {
        buf[i] = buf[i*2];
        if (buf[i] == 0)
            break;
    }
    buf[i] = 0;

    return buf;
}

struct bin_header_t * pac_lookup_FileName(pac_ctx_t *ctx, const char *FileName) {
    int n;

    if (verbose > 0) dprintf("%s %s\n", __func__, FileName);
    for (n = 0; n < ctx->pac_hdr.nFileCount; n++)
    {
         struct bin_header_t *bin_hdr = &ctx->bin_hdr[n];

        if (!strcasecmp(FileName, (char *)(bin_hdr->szFileName))) {
            //dprintf("idx: %d, FileID: %s, FileName: %s,\n", n, (char *)(bin_hdr->szFileID), (char *)(bin_hdr->szFileName));
            return bin_hdr;
        }
    }

    return NULL;
}

struct bin_header_t * pac_lookup_FileID(pac_ctx_t *ctx, const char *FileID) {
    int n;

    //dprintf("%s %s\n", __func__, FileID);

    for (n = 0; n < ctx->pac_hdr.nFileCount; n++)
    {
        struct bin_header_t *bin_hdr = &ctx->bin_hdr[n];

        if (!strcasecmp(FileID, (char *)(bin_hdr->szFileID))) {
            //dprintf("idx: %d, FileID: %s, FileName: %s,\n", n, (char *)(bin_hdr->szFileID), (char *)(bin_hdr->szFileName));
            return bin_hdr;
        }
    }

    return NULL;
}

static Partition_t *pac_lookup_Partition(pac_ctx_t *ctx, const char *Partition) {
    int i;

    for (i = 0; i < ctx->PartitionNum; i++) {
        if (!strcasecmp(Partition, ctx->PartitionList[i].id)) {
            return &ctx->PartitionList[i];
        }
    }

    return NULL;
}

int pac_open_bin(pac_ctx_t *ctx, struct bin_header_t *bin_hdr) {
    int ret;

    if (verbose > 1) dprintf("%s FileID: %s, FileName: %s, Size: %u\n",
        __func__, (char *)(bin_hdr->szFileID), (char *)(bin_hdr->szFileName), bin_hdr->dwLoFileSize);

    ret = fseek(ctx->pac_fp, bin_hdr->dwLoDataOffset, SEEK_SET);
    if (ret)
        return ret;

    ctx->cur_bin_hdr = bin_hdr;
    ctx->cur_bin_offset = 0;

    return 0;
}

int pac_read_bin(pac_ctx_t *ctx, void *pBuf, size_t nSize) {
    FILE *fp = ctx->pac_fp;
    struct bin_header_t *bin_hdr = ctx->cur_bin_hdr;
    int ret;

    if ((ctx->cur_bin_offset + nSize) > bin_hdr->dwLoFileSize)
        nSize = bin_hdr->dwLoFileSize - ctx->cur_bin_offset;

    if (nSize == 0)
        return 0;

    ret = fread(pBuf, 1, nSize, fp);
    if (ret > 0)
        ctx->cur_bin_offset += ret;
    return ret;
}

/*
			<NVBackup backup="1">
				<NVItem name="License" backup="1">
					<ID>0x1BF</ID>
					<BackupFlag use="1">
						<NVFlag name="Continue" check="0"></NVFlag>
					</BackupFlag>
				</NVItem>
			</NVBackup>
*/
int xml_parse_NVBackup(pac_ctx_t *ctx, const char *xml_s, const char *xml_e) {
    const char *p, *pNVItem;
    size_t n, nNVItem;
    uint32_t NVid;

    pNVItem = xml_s;
    while (pNVItem < xml_e) {
        pNVItem = xml_find_node_value(pNVItem, xml_e, "NVItem", &nNVItem);
        if (!pNVItem) goto out;

        p = xml_find_node_value(pNVItem, pNVItem + nNVItem, "ID", &n);
        goto_out(!p);
        pNVItem += nNVItem;

        NVid = strtoul(p, NULL, 16);
        if (NVid < 0xfffe) {
            if (verbose > 0) dprintf("NVBackup[%d] %0x\n", ctx->NVBackupNum, NVid);
            ctx->NVBackupList[ctx->NVBackupNum++] = NVid;
        }
    }

out:
    return 0;
}

int xml_parse_Partition(pac_ctx_t *ctx, const char *xml_s, const char *xml_e) {
    Partition_t Partition;
    char *p;
    size_t n;

    memset(&Partition, 0, sizeof(Partition));

    /* <Partition id="miscdata" size="1"/> */
    p = xml_find_key_value(xml_s, xml_e, "id", &n);
    goto_out(!p);
    strncpy(Partition.id, p, min(n, sizeof(Partition.id)));

    p = xml_find_key_value(xml_s, xml_e, "size", &n);
    goto_out(!p);
    strncpy(Partition.size, p, min(n, sizeof(Partition.size)));

    if (verbose > 0) dprintf("id=\"%s\" size=\"%s\"\n", Partition.id, Partition.size);

    Partition.PartitionSize = strtoul(Partition.size, NULL, !strncmp(Partition.size, "0x", 2) ? 16 : 10);
    if (Partition.PartitionSize != 0xFFFFFFFF)
        Partition.PartitionSize =Partition.PartitionSize*1024*1024;

    ctx->PartitionList[ctx->PartitionNum++] = Partition;

out:
    return 0;
}

/*
            <File>
                <ID>FDL</ID>
                <Block>
                    <Base>0x28007000</Base>
                    <Size>0x0</Size>
                </Block>
            </File>
*/
int xml_parse_File(pac_ctx_t *ctx, const char *xml_s, const char *xml_e, char backup) {
    Scheme_t File;
    char *p, *pBlock;
    size_t n, nBlock;

    memset(&File, 0, sizeof(File));

    File.backup[0] = backup;

    p = xml_find_node_value(xml_s, xml_e, "ID", &n);
    goto_out(!p);
    strncpy(File.FileID, p, min(n, sizeof(File.FileID)));

    File.image = pac_lookup_FileID(ctx, File.FileID);

    p = xml_find_node_value(xml_s, xml_e, "IDAlias", &n);
    goto_out(!p);
    strncpy(File.IDAlias, p, min(n, sizeof(File.IDAlias)));

    p = xml_find_node_value(xml_s, xml_e, "Type", &n);
    goto_out(!p);
    strncpy(File.Type, p, min(n, sizeof(File.Type)));

    pBlock = xml_find_node_header(xml_s, xml_e, "Block", &nBlock);
    goto_out(!pBlock);

    p = xml_find_key_value(pBlock, pBlock + nBlock, "id", &n);
    if (p) {
        strncpy(File.Block, p, min(n, sizeof(File.Block)));
        //dprintf("Partition = \"%s\"\n", File.Block);
        Partition_t *partition = pac_lookup_Partition(ctx, File.Block);

        if (partition) {
            File.partition = partition;
        }
    }

    pBlock = xml_find_node_value(xml_s, xml_e, "Block", &nBlock);
    goto_out (!pBlock && strcmp(File.FileID, "FDL") && strcmp(File.FileID, "FDL2"));

    p = xml_find_node_value(pBlock, pBlock + nBlock, "Base", &n);
    if (p)
        strncpy(File.Base, p, min(n, sizeof(File.Base)));

    p = xml_find_node_value(pBlock, pBlock + nBlock, "Size", &n);
    if (p && strncmp(p, "0x0", n))
    {
        strncpy(File.Size, p, min(n, sizeof(File.Size)));
    }

    if (udx710 == 1)
    {
        int i;
        for (i = 0; i < ctx->pac_hdr.nFileCount; i++)
        {
            struct bin_header_t *bin_hdr = &ctx->bin_hdr[i];
            if (strcmp((const char*)bin_hdr->szFileID, File.IDAlias) == 0){
                sprintf(File.Flag,"%d",bin_hdr->_nFileFlag);
                sprintf(File.CheckFlag,"%d",bin_hdr->_nCheckFlag);
                break;
            }
            if (strcmp((const char*)bin_hdr->szFileID, File.FileID) == 0){
                sprintf(File.Flag,"%d",bin_hdr->_nFileFlag);
                sprintf(File.CheckFlag,"%d",bin_hdr->_nCheckFlag);
                break;
            }
        }
    }else
    {
        p = xml_find_node_value(xml_s, xml_e, "Flag", &n);
        goto_out(!p);
        strncpy(File.Flag, p, min(n, sizeof(File.Flag)));

        p = xml_find_node_value(xml_s, xml_e, "CheckFlag", &n);
        goto_out(!p);
        strncpy(File.CheckFlag, p, min(n, sizeof(File.CheckFlag)));
    }

    ctx->SchemeList[ctx->SchemeNum++] = File;

    return 1;
out:
    return 0;
}

void xml_delete_comment(char *xml_buf, size_t xml_len) {
    //<!--    -->
    char *pFind = NULL;
    int nFind = 0;
    char *p = xml_buf;
    char *xml_end = xml_buf + xml_len;

    while (p && p < xml_end && *p) {
        char *s = strstr(p, "<!--");

        if (nFind == 0) {
            assert(pFind == NULL);
            if (s) {
                //dprintf("%.32s\n", s);
                nFind++;
                pFind = s;
            }

            p = s ? s + 4 : NULL;
        }
        else {
            char *e = strstr(p, "-->");

            assert(pFind != NULL);
            assert(e);
            if (!s || s > e) {
                    //dprintf("%.3s\n", e);
                    nFind--;
                    if (nFind == 0) {
                        memset(pFind, ' ', e + 3 - pFind);
                        pFind = NULL;
                    }

                    p = e ? e + 3 : NULL;
            }
            else if (s && s < e) {
                    //dprintf("%.16s\n", s);
                    nFind++;
                    p = s ? s + 4 : NULL;
            }
            else {
                assert(0);
            }
        }
    }
}

/*
<BMAConfig>
    <ProductList>
        <Product name="udx710-module">
            <SchemeName>udx710-module</SchemeName>
            <FlashTypeID>1</FlashTypeID>
            <NVBackup backup="1">
            </NVBackup>
            <Partitions>
            </Partitions>
        </Product>
    </ProductList>
    <SchemeList>
        <Scheme name="udx710-module">
            <File>
            </File>
        </Scheme>
    </SchemeList>
</BMAConfig>
*/

static int xml_parser(pac_ctx_t *ctx, char *xml_buf, size_t xml_len) {
    int n;
    char *pBMAConfig;
    char *pProductList, *pProduct, *pPartitions, *pPartition;
    char *pSchemeList, *pScheme, *pFile;
    char *pNVBackup;
    size_t nBMAConfig;
    size_t nProductList, nProduct, nPartitions, nPartition;
    size_t nSchemeList, nScheme, nFile;
    size_t nNVBackup;

    xml_delete_comment(xml_buf, xml_len);

    pBMAConfig = xml_find_node_value(xml_buf, xml_buf + xml_len, "BMAConfig", &nBMAConfig);
    goto_out(!pBMAConfig);

    pProductList = xml_find_node_value(pBMAConfig, pBMAConfig + nBMAConfig, "ProductList", &nProductList);
    goto_out(!pProductList);

    pProduct = xml_find_node_value(pProductList, pProductList + nProductList, "Product", &nProduct);
    goto_out(!pProduct);

    pNVBackup = xml_find_node_value(pProduct, pProduct + nProduct, "NVBackup", &nNVBackup);
    goto_out(!pNVBackup);

    xml_parse_NVBackup(ctx, pNVBackup, pNVBackup + nNVBackup);

    pPartitions = xml_find_node_value(pProduct, pProduct + nProduct, "Partitions", &nPartitions);
    if (!pPartitions) goto _skip_partition; // UIX8910_MODEM no partition

    pPartition = pPartitions;
    while (pPartition) {
        pPartition = xml_find_node_value(pPartition, pPartitions + nPartitions, "Partition", &nPartition);
        if (pPartition) {
            xml_parse_Partition(ctx, pPartition, pPartition + nPartition);
        }
    };

_skip_partition:
    pSchemeList = xml_find_node_value(pBMAConfig, pBMAConfig + nBMAConfig, "SchemeList", &nSchemeList);
    goto_out(!pSchemeList);

    pScheme = xml_find_node_value(xml_buf, pSchemeList + nSchemeList, "SchemeList", &nScheme);
    goto_out(!pScheme);

    pFile = pScheme;
    while (pFile) {
        char *p;
        char backup[2] = "0";

        p = xml_find_node_header(pFile, pScheme + nScheme, "File", &nFile);
        if (p) {

            p = xml_find_key_value(p, p + nFile, "backup", &nFile);
            if (p) {
                strncpy(backup, p, min(nFile, sizeof(backup)));
                //dprintf("backup =\"%c\"\n", backup[0]);
            }
        }

        pFile = xml_find_node_value(pFile, pScheme + nScheme, "File", &nFile);
        if (pFile) {
            xml_parse_File(ctx, pFile, pFile + nFile, backup[0]);
        }
    };

    if (verbose > 0) dprintf("%-20s%-16s%-12s%-12s%s\n", "FileID", "Base", "Size", "FileSize", "FileName");
    for (n = 0; n < ctx->SchemeNum; n++) {
        Scheme_t *File =  &ctx->SchemeList[n];
        const char *PartitionBase = File->Base;
        const char *FileName = NULL;
        char PartitionSizeStr[32] = "";
        char FileSizeStr[32] = "";

        File->PartitionSize = strtoul(File->Size, NULL, !strncmp(File->Size, "0x", 2) ? 16 : 10);
        if (File->partition) {
            PartitionBase = File->partition->id;
            File->PartitionSize = File->partition->PartitionSize;
        }

        if (File->image) {
            FileName = (const char *)File->image->szFileName;
            snprintf(FileSizeStr, 32, "0x%08X", File->image->dwLoFileSize);
        }

        if (File->PartitionSize) {
            snprintf(PartitionSizeStr, 32, "0x%08X", File->PartitionSize);
        }

        if (verbose > 0) dprintf("%-20s%-16s%-12s%-12s%s\n", File->IDAlias, PartitionBase, PartitionSizeStr, FileSizeStr, FileName);
    }

out:
    return 0;
}

static int pac_parser_xml(pac_ctx_t *ctx)
{
    char szPrdName[64];
    struct bin_header_t *bin_hdr = NULL;
    int ret = -1;

    snprintf(szPrdName, sizeof(szPrdName), "%.32s.xml", (char *)(ctx->pac_hdr.szPrdName));
    bin_hdr = pac_lookup_FileName(ctx, szPrdName);
    if (!bin_hdr)
        bin_hdr = pac_lookup_FileID(ctx, "");

    if (!bin_hdr)
        goto out;

    if (pac_open_bin(ctx, bin_hdr))
        goto out;

    ctx->xml_len = bin_hdr->dwLoFileSize;
    ctx->xml_buf = (char *)malloc(ctx->xml_len + 32);
    if (!ctx->xml_buf)
        goto out;

    ctx->xml_len = pac_read_bin(ctx, ctx->xml_buf, ctx->xml_len);
    if (ctx->xml_len < 1024)
        goto out;
    memset(&ctx->xml_buf[ctx->xml_len], 0, 32);

    ret = xml_parser(ctx, ctx->xml_buf, ctx->xml_len);

out:
    return ret;
}

int pac_parser( pac_ctx_t *ctx, FILE *fw_fp)
{
    struct pac_header_t *pachdr = &ctx->pac_hdr;
    FILE *fp = fw_fp;
    ssize_t n;

    n = fread(pachdr, 1, sizeof(struct pac_header_t), fp);
    if (n != sizeof(struct pac_header_t))
         return -1;

    if (pachdr->nFileCount > 64)
        return -1;

    n = fread(ctx->bin_hdr, 1, sizeof(struct bin_header_t) * pachdr->nFileCount, fp);
    if (n != (sizeof(struct bin_header_t) * pachdr->nFileCount))
         return -1;

    wcharToChar(pachdr->szVersion, sizeof(pachdr->szVersion));
    wcharToChar(pachdr->szPrdName, sizeof(pachdr->szPrdName));
    wcharToChar(pachdr->szPrdVersion, sizeof(pachdr->szPrdVersion));
    wcharToChar(pachdr->szPrdAlias, sizeof(pachdr->szPrdAlias));
    pachdr->nFileCount = le32toh(pachdr->nFileCount);

    dprintf("Version: %s\n", (char *)(pachdr->szVersion));
    dprintf("ProductName: %s\n", (char *)(pachdr->szPrdName));
    dprintf("ProductVersion: %s\n", (char *)(pachdr->szPrdVersion));
    dprintf("szPrdAlias: %s\n", (char *)(pachdr->szPrdAlias));

    for (n = 0; n < pachdr->nFileCount; n++)
    {
        struct bin_header_t *bin_hdr = &ctx->bin_hdr[n];

        wcharToChar(bin_hdr->szFileID, sizeof(bin_hdr->szFileID));
        wcharToChar(bin_hdr->szFileName, sizeof(bin_hdr->szFileName));
        wcharToChar(bin_hdr->szFileVersion, sizeof(bin_hdr->szFileVersion));
        bin_hdr->dwLoFileSize = le32toh(bin_hdr->dwLoFileSize);
        bin_hdr->dwLoDataOffset = le32toh(bin_hdr->dwLoDataOffset);

        if (udx710 == 1)
        {
            bin_hdr->_nFileFlag = le32toh(bin_hdr->_nFileFlag);
            bin_hdr->_nCheckFlag = le32toh(bin_hdr->_nCheckFlag);

            /* dprintf("idx: %zd, FileID: %s, FileName: %s, szFileVersion: %s, Size: %u, _nFileFlag:%u,_nCheckFlag:%u\n",
                n, (char *)(bin_hdr->szFileID), (char *)(bin_hdr->szFileName),
                (char *)bin_hdr->szFileVersion,  bin_hdr->dwLoFileSize,bin_hdr->_nFileFlag, bin_hdr->_nCheckFlag); */
        }else
        {
            if (verbose > 0) dprintf("idx: %zd, FileID: %s, FileName: %s, szFileVersion: %s, Size: %u\n",
             n, (char *)(bin_hdr->szFileID), (char *)(bin_hdr->szFileName),
             (char *)bin_hdr->szFileVersion,  bin_hdr->dwLoFileSize);
        }
    }

    ctx->pac_fp = fp;
    if (pac_parser_xml(ctx)) {
        return -1;
    }

    return 0;
}
