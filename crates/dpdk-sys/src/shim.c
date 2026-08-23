#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_mempool.h>

struct nt_rx_packet {
    struct rte_mbuf *mbuf;
    const uint8_t *data;
    uint32_t data_len;
    uint32_t packet_len;
    uint32_t rss_hash;
    uint64_t offload_flags;
};

struct nt_dpdk_port_stats {
    uint64_t ipackets;
    uint64_t opackets;
    uint64_t ibytes;
    uint64_t obytes;
    uint64_t imissed;
    uint64_t ierrors;
    uint64_t oerrors;
    uint64_t rx_nombuf;
};

int nt_dpdk_eal_init(int argc, char **argv) { return rte_eal_init(argc, argv); }
int nt_dpdk_eal_cleanup(void) { return rte_eal_cleanup(); }
uint16_t nt_dpdk_port_count(void) { return rte_eth_dev_count_avail(); }
int nt_dpdk_port_by_name(const char *name, uint16_t *port_id) {
    return rte_eth_dev_get_port_by_name(name, port_id);
}

struct rte_mempool *nt_dpdk_mempool_create(const char *name, unsigned count,
                                            unsigned cache_size,
                                            uint16_t data_room_size,
                                            int socket_id) {
    return rte_pktmbuf_pool_create(name, count, cache_size, 0, data_room_size,
                                   socket_id);
}

void nt_dpdk_mempool_free(struct rte_mempool *pool) { rte_mempool_free(pool); }

int nt_dpdk_port_configure(uint16_t port_id, uint16_t rx_queues,
                           uint16_t tx_queues, uint16_t rx_descriptors,
                           uint16_t tx_descriptors, struct rte_mempool *pool,
                           unsigned socket_id) {
    struct rte_eth_conf port_conf;
    struct rte_eth_dev_info info;
    memset(&port_conf, 0, sizeof(port_conf));
    memset(&info, 0, sizeof(info));
    int result = rte_eth_dev_info_get(port_id, &info);
    if (result < 0) return result;
    result = rte_eth_dev_configure(port_id, rx_queues, tx_queues, &port_conf);
    if (result < 0) return result;
    result = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &rx_descriptors,
                                               &tx_descriptors);
    if (result < 0) return result;
    for (uint16_t queue = 0; queue < rx_queues; ++queue) {
        result = rte_eth_rx_queue_setup(port_id, queue, rx_descriptors,
                                        socket_id, &info.default_rxconf, pool);
        if (result < 0) return result;
    }
    for (uint16_t queue = 0; queue < tx_queues; ++queue) {
        result = rte_eth_tx_queue_setup(port_id, queue, tx_descriptors,
                                        socket_id, &info.default_txconf);
        if (result < 0) return result;
    }
    return 0;
}

int nt_dpdk_port_start(uint16_t port_id) { return rte_eth_dev_start(port_id); }

void nt_dpdk_port_stop_close(uint16_t port_id) {
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);
}

uint16_t nt_dpdk_rx_burst(uint16_t port_id, uint16_t queue_id,
                          struct nt_rx_packet *packets, uint16_t capacity) {
    struct rte_mbuf *mbufs[256];
    if (capacity > 256) capacity = 256;
    uint16_t received = rte_eth_rx_burst(port_id, queue_id, mbufs, capacity);
    for (uint16_t index = 0; index < received; ++index) {
        struct rte_mbuf *mbuf = mbufs[index];
        packets[index].mbuf = mbuf;
        packets[index].data = rte_pktmbuf_mtod(mbuf, const uint8_t *);
        packets[index].data_len = rte_pktmbuf_data_len(mbuf);
        packets[index].packet_len = rte_pktmbuf_pkt_len(mbuf);
        packets[index].rss_hash = mbuf->hash.rss;
        packets[index].offload_flags = mbuf->ol_flags;
    }
    return received;
}

int nt_dpdk_tx_template_burst(uint16_t port_id, uint16_t queue_id,
                              struct rte_mempool *pool, const uint8_t *data,
                              uint16_t data_length, uint16_t count) {
    struct rte_mbuf *mbufs[256];
    if (count == 0 || count > 256 || data == NULL || data_length == 0) {
        return -EINVAL;
    }
    if (rte_pktmbuf_alloc_bulk(pool, mbufs, count) < 0) {
        return -rte_errno;
    }
    for (uint16_t index = 0; index < count; ++index) {
        uint8_t *destination = rte_pktmbuf_append(mbufs[index], data_length);
        if (destination == NULL) {
            for (uint16_t pending = 0; pending < count; ++pending) {
                rte_pktmbuf_free(mbufs[pending]);
            }
            return -ENOSPC;
        }
        rte_memcpy(destination, data, data_length);
    }
    uint16_t sent = rte_eth_tx_burst(port_id, queue_id, mbufs, count);
    for (uint16_t index = sent; index < count; ++index) {
        rte_pktmbuf_free(mbufs[index]);
    }
    return (int)sent;
}

int nt_dpdk_port_stats_get(uint16_t port_id, struct nt_dpdk_port_stats *stats) {
    if (stats == NULL) return -EINVAL;
    struct rte_eth_stats current;
    memset(&current, 0, sizeof(current));
    int result = rte_eth_stats_get(port_id, &current);
    if (result < 0) return result;
    stats->ipackets = current.ipackets;
    stats->opackets = current.opackets;
    stats->ibytes = current.ibytes;
    stats->obytes = current.obytes;
    stats->imissed = current.imissed;
    stats->ierrors = current.ierrors;
    stats->oerrors = current.oerrors;
    stats->rx_nombuf = current.rx_nombuf;
    return 0;
}

int nt_dpdk_port_xstats_get(uint16_t port_id, char *names, uint32_t name_width,
                            uint64_t *values, uint32_t capacity) {
    if (name_width == 0) return -EINVAL;
    int count = rte_eth_xstats_get_names(port_id, NULL, 0);
    if (count < 0) return count;
    if (capacity < (uint32_t)count || names == NULL || values == NULL) return count;
    struct rte_eth_xstat_name *native_names = calloc((size_t)count, sizeof(*native_names));
    struct rte_eth_xstat *native_values = calloc((size_t)count, sizeof(*native_values));
    if (native_names == NULL || native_values == NULL) {
        free(native_names);
        free(native_values);
        return -ENOMEM;
    }
    int named = rte_eth_xstats_get_names(port_id, native_names, (unsigned)count);
    int measured = rte_eth_xstats_get(port_id, native_values, (unsigned)count);
    if (named < 0 || measured < 0 || named != measured) {
        free(native_names);
        free(native_values);
        return named < 0 ? named : (measured < 0 ? measured : -EIO);
    }
    for (int index = 0; index < count; ++index) {
        char *destination = names + ((size_t)index * name_width);
        memset(destination, 0, name_width);
        size_t source_length = 0;
        while (source_length < RTE_ETH_XSTATS_NAME_SIZE &&
               native_names[index].name[source_length] != '\0') {
            ++source_length;
        }
        size_t copy_length = source_length < (size_t)(name_width - 1)
                                 ? source_length
                                 : (size_t)(name_width - 1);
        memcpy(destination, native_names[index].name, copy_length);
        values[index] = native_values[index].value;
    }
    free(native_names);
    free(native_values);
    return count;
}

void nt_dpdk_mbuf_free(struct rte_mbuf *mbuf) { rte_pktmbuf_free(mbuf); }
int nt_dpdk_errno(void) { return rte_errno; }
const char *nt_dpdk_strerror(int error) { return rte_strerror(error); }
