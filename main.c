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

struct dst_exthdr {
	__u8    nexthdr;
	__u8    hdrlen;
	__u8    opttype;
	__u8    optdatalen;
	__u8	geotype;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	res:5,
		t:1,
		a:1,
		l:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	res:5,
		l:1,
		a:1,
		t:1;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
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
};

static struct kobject *geoinfo;
static struct user_geoinfo *ugeo;

static ssize_t
int_latitude_show(struct kobject *kobj,
		  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", ugeo->int_lat);
}

static ssize_t
int_latitude_store(struct kobject *kobj, struct kobj_attribute *attr,
		   const char *buf, size_t count)
{
	sscanf(buf, "%hd", &ugeo->int_lat);
	return count;
}

static ssize_t
int_longitude_show(struct kobject *kobj,
		   struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", ugeo->int_lon);
}

static ssize_t
int_longitude_store(struct kobject *kobj, struct kobj_attribute *attr,
		    const char *buf, size_t count)
{
	sscanf(buf, "%hd", &ugeo->int_lon);
	return count;
}

static ssize_t
frac_latitude_show(struct kobject *kobj,
		   struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", ugeo->frac_lat);
}

static ssize_t
frac_latitude_store(struct kobject *kobj, struct kobj_attribute *attr,
		    const char *buf, size_t count)
{
	sscanf(buf, "%d", &ugeo->frac_lat);
	return count;
}

static ssize_t
frac_longitude_show(struct kobject *kobj,
		    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", ugeo->frac_lon);
}

static ssize_t
frac_longitude_store(struct kobject *kobj, struct kobj_attribute *attr,
		     const char *buf, size_t count)
{
	sscanf(buf, "%d", &ugeo->frac_lon);
	return count;
}

struct sk_buff *
insert_dest_ext_header(struct sk_buff *skb)
{
	struct sk_buff *newskb;
	struct ipv6hdr *ip6h = ipv6_hdr(skb);
	struct dst_exthdr *deh;
	struct timeval tv;
	unsigned int nexthdr = ip6h->nexthdr;

	pr_info("%s\n", __func__);

	ip6h->nexthdr = NEXTHDR_DEST;
	ip6h->payload_len = htons(ntohs(ip6h->payload_len)
				  + sizeof(struct dst_exthdr));

	newskb = skb_copy_expand(skb, skb_headroom(skb),
				 skb_tailroom(skb) + sizeof(struct dst_exthdr),
				 GFP_ATOMIC);

	if (newskb == NULL) {
		pr_err("Allocate new sk_buffer error\n");
		return NULL;
	}

	if (skb->sk != NULL)
		skb_set_owner_w(newskb, skb->sk);

	skb_put(newskb, sizeof(struct dst_exthdr));

	memcpy(newskb->data, skb->data, sizeof(struct ipv6hdr));
	memcpy(newskb->data + sizeof(struct ipv6hdr) + sizeof(struct dst_exthdr)
	       ,skb->data + sizeof(struct ipv6hdr)
	       ,skb->len - sizeof(struct ipv6hdr));

	skb = newskb;
	deh = (struct dst_exthdr *)(skb->data + sizeof(struct ipv6hdr));

	deh->nexthdr = nexthdr;
	deh->hdrlen = 0x03;
	deh->opttype = 0x1e;	// For experimental(RFC 4727)
	deh->optdatalen = 0x1c;
	deh->geotype = 0x00;
	deh->res = 0x00;
	deh->t = 0x01;
	deh->a = 0x01;
	deh->l = 0x01;
	// 35.681368, 139.766076
	deh->intpart = 0xb107;
	deh->latfracpart = 0x40faf60;
	deh->lonfracpart = 0x490f070;
	// 3698.754638671875m(Mt. Fuji)
	deh->alt = 0x40ace58260000000;

	do_gettimeofday(&tv);
	deh->sec = htonl(tv.tv_sec);
	deh->usec = htonl(tv.tv_usec);

	return skb;
}

static unsigned
int handle_tx_pkt(void *priv,
		  struct sk_buff *skb,
		  const struct nf_hook_state *state)
{
	struct ipv6hdr *ip6h = ipv6_hdr(skb);

	if (ip6h->nexthdr != NEXTHDR_DEST) {
		pr_info("%s\n", __func__);
		skb = insert_dest_ext_header(skb);
		state->okfn(state->net, state->sk, skb);

		return NF_STOLEN;
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

		pr_info("func:%s, ipv6->nexthdr:%x\n", __func__, ip6h->nexthdr);
		pr_info("func:%s, dsthdr->nexthdr:%x, dsthdr->hdrlen:%x\n",
			__func__, deh->nexthdr, deh->hdrlen);
		pr_info("opttype: %x\n", deh->opttype);
		pr_info("optdatalen: %x\n", deh->optdatalen);

		if (deh->nexthdr == NEXTHDR_TCP) {
			struct tcphdr *tcph = (struct tcphdr *)
				(skb->data + sizeof(struct ipv6hdr)
				 + sizeof(struct dst_exthdr));

			pr_info("src port: %d\n", htons(tcph->source));
			pr_info("dst port: %d\n", htons(tcph->dest));
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

static int  __init geov6_init(void)
{
	int ret;

	pr_info("%s\n", __func__);

	ugeo = kmalloc(sizeof(struct user_geoinfo), GFP_KERNEL);
	memset(ugeo, 0, sizeof(struct user_geoinfo));

	geoinfo = kobject_create_and_add("geov6", kernel_kobj);
	if (!geoinfo)
		return -ENOMEM;

	ret = sysfs_create_file(geoinfo, &sys_intlat.attr);
	if (ret < 0)
		return ret;

	ret = sysfs_create_file(geoinfo, &sys_intlon.attr);
	if (ret < 0)
		return ret;

	ret = sysfs_create_file(geoinfo, &sys_fraclat.attr);
	if (ret < 0)
		return ret;

	ret = sysfs_create_file(geoinfo, &sys_fraclon.attr);
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
