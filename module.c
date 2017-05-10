#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <net/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip_vs.h>
#include <linux/time.h>
#include <linux/sysfs.h>
#include <linux/fs.h>

#define BIT_FLAG_T 0x01
#define BIT_FLAG_A 0x02
#define BIT_FLAG_L 0x04

static int debug = 0;

struct dst_exthdr {
	__u8    nexthdr;
	__u8    hdrlen;
	__u8    opttype;
	__u8    optdatalen;
	__u8	geotype;
	__u8	reserve;
	__u16   intpart;
	__u32   latfracpart;
	__u32   lonfracpart;
	__u64   alt;
	__u32   sec;
	__u32   usec;
} __attribute__((packed));


struct user_geoinfo {
	u16	int_lat;
	u16	int_lon;
	u32	frac_lat;
	u32	frac_lon;
	spinlock_t lock;
};

static struct kobject *geoinfo;
static struct user_geoinfo *ugeo;

static ssize_t
int_latitude_show(struct kobject *kobj,
		  struct kobj_attribute *attr, char *buf)
{
	spin_lock_bh(&ugeo->lock);
	sprintf(buf, "%d\n", ugeo->int_lat);
	spin_unlock_bh(&ugeo->lock);

	return strlen(buf);
}

static ssize_t
int_latitude_store(struct kobject *kobj, struct kobj_attribute *attr,
		   const char *buf, size_t count)
{
	if (buf == '\0')
		buf = 0x0000;

	spin_lock_bh(&ugeo->lock);
	sscanf(buf, "%hd", &ugeo->int_lat);
	spin_unlock_bh(&ugeo->lock);

	return count;
}

static ssize_t
int_longitude_show(struct kobject *kobj,
		   struct kobj_attribute *attr, char *buf)
{
	spin_lock_bh(&ugeo->lock);
	sprintf(buf, "%d\n", ugeo->int_lon);
	spin_unlock_bh(&ugeo->lock);

	return strlen(buf);
}

static ssize_t
int_longitude_store(struct kobject *kobj, struct kobj_attribute *attr,
		    const char *buf, size_t count)
{
	if (buf == '\0')
		buf = 0x0000;

	spin_lock_bh(&ugeo->lock);
	sscanf(buf, "%hd", &ugeo->int_lon);
	spin_unlock_bh(&ugeo->lock);

	return count;
}

static ssize_t
frac_latitude_show(struct kobject *kobj,
		   struct kobj_attribute *attr, char *buf)
{
	spin_lock_bh(&ugeo->lock);
	sprintf(buf, "%d\n", ugeo->frac_lat);
	spin_unlock_bh(&ugeo->lock);

	return strlen(buf);
}

static ssize_t
frac_latitude_store(struct kobject *kobj, struct kobj_attribute *attr,
		    const char *buf, size_t count)
{
	if (buf == '\0')
		buf = 0x00000000;

	spin_lock_bh(&ugeo->lock);
	sscanf(buf, "%d", &ugeo->frac_lat);
	spin_unlock_bh(&ugeo->lock);

	return count;
}

static ssize_t
frac_longitude_show(struct kobject *kobj,
		    struct kobj_attribute *attr, char *buf)
{
	spin_lock_bh(&ugeo->lock);
	sprintf(buf, "%d\n", ugeo->frac_lon);
	spin_unlock_bh(&ugeo->lock);

	return strlen(buf);
}

static ssize_t
frac_longitude_store(struct kobject *kobj, struct kobj_attribute *attr,
		     const char *buf, size_t count)
{
	if (buf == '\0')
		buf = 0x00000000;

	spin_lock_bh(&ugeo->lock);
	sscanf(buf, "%d", &ugeo->frac_lon);
	spin_unlock_bh(&ugeo->lock);

	return count;
}

static inline int
encode_integer_part(void)
{
	if ((ugeo->int_lat != 0) && (ugeo->int_lon != 0))
		return (ugeo->int_lat + 90) * 360 + (ugeo->int_lon + 180);
	else
		return 0;
}

static inline int
encode_fraction_latitude(void)
{
	if (ugeo->frac_lat != 0)
		return ugeo->frac_lat * 1000000000;
	else
		return 0;
}

static inline int
encode_fraction_longitude(void)
{
	if (ugeo->frac_lon != 0)
		return ugeo->frac_lon * 1000000000;
	else
		return 0;
}

void
insert_dest_ext_header(struct sk_buff *skb,
		       int offset, int nexthdr)
{
	struct dst_exthdr *deh;
	struct timeval tv;

	deh = (struct dst_exthdr *)(skb->data + offset);

	deh->nexthdr = nexthdr;
        deh->hdrlen = 0x03;
        deh->opttype = 0x1e;    // For experimental(RFC 4727)
        deh->optdatalen = 0x1c;
        deh->geotype = 0x00;
        deh->reserve = BIT_FLAG_T | BIT_FLAG_A | BIT_FLAG_L;
        // 35.681368, 139.766076
        deh->intpart = encode_integer_part();
        deh->latfracpart = encode_fraction_latitude();
        deh->lonfracpart = encode_fraction_longitude();
        // 3698.754638671875m(Mt. Fuji)
        deh->alt = 0x40ace58260000000;

        do_gettimeofday(&tv);
        deh->sec = htonl(tv.tv_sec);
        deh->usec = htonl(tv.tv_usec);
}

static unsigned
int handle_tx_pkt(void *priv,
		  struct sk_buff *skb,
		  const struct nf_hook_state *state)
{
	struct ipv6hdr *ip6h = ipv6_hdr(skb);
	unsigned int nexthdr;

	/* FIXME This module cannot be applied to
	 * other ipv6 extension headers */
	if (ip6h->nexthdr == NEXTHDR_TCP
	    || ip6h->nexthdr == NEXTHDR_UDP
	    || ip6h->nexthdr == NEXTHDR_ICMP) {

		// check if headroom is enough
		if (skb_headroom(skb) < sizeof(struct dst_exthdr) + ETH_HLEN) {
			if (pskb_expand_head(skb,
				SKB_DATA_ALIGN(sizeof(struct dst_exthdr)
				+ ETH_HLEN) - skb_headroom(skb),
				0, GFP_ATOMIC) != 0) {
				pr_err("Reallocate headroom error\n");
				return NF_DROP;
			}
		}

		// expand sk_buff space
		skb_push(skb, sizeof(struct dst_exthdr));
		memmove(skb->data, ip6h, sizeof(struct ipv6hdr));

		// reset ipv6 header
		skb_reset_network_header(skb);
		ip6h = ipv6_hdr(skb);

		memset(skb->data + sizeof(struct ipv6hdr), 0,
		       sizeof(struct dst_exthdr));

		// construct destination header
		nexthdr = ip6h->nexthdr;
		insert_dest_ext_header(skb, sizeof(struct ipv6hdr)
				       + sizeof(struct dst_exthdr),
				       nexthdr);

		// set ipv6 header
		ip6h->nexthdr = NEXTHDR_DEST;
		ip6h->payload_len = htons(ntohs(ip6h->payload_len)
					  + sizeof(struct dst_exthdr));

	}

	return NF_ACCEPT;
}

static unsigned
int handle_rx_pkt(void *priv,
		  struct sk_buff *skb,
		  const struct nf_hook_state *state)
{
	struct ipv6hdr *ip6h = ipv6_hdr(skb);

	// catch destination option header
	if (ip6h->nexthdr == NEXTHDR_DEST) {
		struct dst_exthdr *deh = (struct dst_exthdr *)
			(skb->data + sizeof(struct ipv6hdr));

		if (debug) {
			pr_info("func:%s, ipv6->nexthdr:%x\n",
				__func__, ip6h->nexthdr);
			pr_info("func:%s, dsthdr->nexthdr:%x, dsthdr->hdrlen:%x\n"
				, __func__, deh->nexthdr, deh->hdrlen);
			pr_info("opttype: %x\n", deh->opttype);
			pr_info("optdatalen: %x\n", deh->optdatalen);
		}
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops tx_hook_ops = {
	.hook     = handle_tx_pkt,
	.pf       = PF_INET6,
	.hooknum  = NF_INET_LOCAL_OUT,
	.priority = NF_IP6_PRI_FILTER,
};

static struct nf_hook_ops rx_hook_ops = {
	.hook     = handle_rx_pkt,
	.pf       = PF_INET6,
	.hooknum  = NF_INET_LOCAL_IN,
	.priority = NF_IP6_PRI_FILTER,
};

static struct kobj_attribute sys_intlat = __ATTR_RW(int_latitude);
static struct kobj_attribute sys_intlon = __ATTR_RW(int_longitude);
static struct kobj_attribute sys_fraclat = __ATTR_RW(frac_latitude);
static struct kobj_attribute sys_fraclon = __ATTR_RW(frac_longitude);

static struct attribute *attrs[] = {
	&sys_intlat.attr,
	&sys_intlon.attr,
	&sys_fraclat.attr,
	&sys_fraclon.attr,
	NULL,
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};

static int  __init geov6_init(void)
{
	int ret;

	pr_info("%s\n", __func__);

	ugeo = kmalloc(sizeof(struct user_geoinfo), GFP_KERNEL);
	if (!ugeo) {
		pr_err("Failed to kmalloc\n");
		return -1;
	}

	memset(ugeo, 0, sizeof(struct user_geoinfo));
	spin_lock_init(&ugeo->lock);

	geoinfo = kobject_create_and_add("geov6", kernel_kobj);
	if (!geoinfo)
		return -ENOMEM;

	ret = sysfs_create_group(geoinfo, &attr_group);
	if (ret < 0)
		return ret;

	ret = nf_register_hook(&tx_hook_ops);
	if (ret < 0)
		return ret;

	ret = nf_register_hook(&rx_hook_ops);
	if (ret < 0)
		return ret;

	return 0;
}

static void __exit geov6_exit(void)
{
	pr_info("%s\n", __func__);

	nf_unregister_hook(&tx_hook_ops);
	nf_unregister_hook(&rx_hook_ops);

	kobject_put(geoinfo);
	kfree(ugeo);
}

module_init(geov6_init);
module_exit(geov6_exit);

MODULE_AUTHOR("KIMOTO Mizuki");
MODULE_DESCRIPTION("Kernel module for extension ipv6 header");
MODULE_LICENSE("GPL");
module_param(debug, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug, "Enable debug mode");
