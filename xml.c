#include "std_c.h"

char * xml_find_key_value(const char *xml_s, const char *xml_e, const char *key, size_t *pSize)
{
    char *p = NULL;
    size_t n = 0;

    /* <Partition id="miscdata" size = "1"/> */
    p = strstr(xml_s, key);
    if (!p || p > xml_e)
        return NULL;

    p = strstr(p + strlen(key), "=");
    if (!p || p > xml_e)
        return NULL;

    p = strstr(p + strlen("="), "\"");
    if (!p || p > xml_e)
        return NULL;

    p++;
    n = 0;
    while (p < xml_e && p[n] && p[n] != '\"') {
            n++;
    }

    if (p[n] != '\"')
        return NULL;

    *pSize = n;
    return p;
}

char * xml_find_node_header(const char *xml_s, const char *xml_e, const char *node, size_t *pSize) {
    char *p = NULL;
    char node_s[128];
    size_t n;

    snprintf(node_s, sizeof(node_s), "<%s", node);
    p = strstr(xml_s, node_s);
    if (!p || p > xml_e)
        return NULL;

    n = strlen(node);
    while (p < xml_e && p[n] && p[n] != '>') {
            n++;
    }

    if (p[n] != '>')
        return NULL;

    n++;
    *pSize = n;
    return p;
}

char * xml_find_node_value(const char *xml_s, const char *xml_e, const char *node, size_t *pSize)
{
    char *p = NULL;
    char *e = NULL;
    char node_s[128];
    size_t n;

    /* <ID>FDL</ID> */
    p = xml_find_node_header(xml_s, xml_e, node, &n);
    if (!p) goto out;

    if (p[n-2] == '/') {
        /* <Partition id="miscdata" size="1"/> */
        p += (strlen(node) + strlen("<"));
        n -= (strlen(node) + strlen("<") +  + strlen("/>"));

        *pSize = n;
        return p;
    }

    p += n;
    snprintf(node_s, sizeof(node_s), "</%s>", node);
    e = strstr(p, node_s);
    if (!e || e > xml_e)
        return NULL;

    n = e - p;
    if (n < 16) {
#if 0
        char buf[16];
        memcpy(buf, p, n);
         buf[n] = 0;
        dprintf("%-16s: %s\n", node, buf);
#endif
    }

    *pSize = n;
    return p;

out:
    return NULL;
}
