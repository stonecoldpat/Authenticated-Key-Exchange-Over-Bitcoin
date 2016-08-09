#include "YAK.h"

#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <memory.h>

/*
 * In the definition, (xa, xb, xc, xd) are Alice's (x1, x2, x3, x4) or
 * Bob's (x3, x4, x1, x2). If you see what I mean.
 */

typedef struct
{
    char *name;  /* Must be unique */
    char *peer_name;
    BIGNUM *p; //modulus p
    BIGNUM *g; //generator
    BIGNUM *q; //group order
} YAK_CTX_PUBLIC;

struct YAK_CTX
{
    YAK_CTX_PUBLIC p;
    EC_POINT *secret;   /* The shared secret */
    BIGNUM *k; /* Random nonce k */
    BN_CTX *ctx;
    BIGNUM *xa;       /* Alice's x1 or Bob's x3 */
    BIGNUM *key;      /* The calculated (shared) key */
};

static void YAK_ZKP_init(YAK_ZKP *zkp)
{
    zkp->gr = BN_new();
    zkp->b = BN_new();
}

static void YAK_ZKP_release(YAK_ZKP *zkp)
{
    BN_free(zkp->b);
    BN_free(zkp->gr);
}

/* Two birds with one stone - make the global name as expected */
#define YAK_STEP_PART_init	YAK_STEP2_init
#define YAK_STEP_PART_release	YAK_STEP2_release

void YAK_STEP_PART_init(YAK_STEP_PART *p)
{
    p->gx = BN_new();
    YAK_ZKP_init(&p->zkpx);
}

void YAK_STEP_PART_release(YAK_STEP_PART *p)
{
    YAK_ZKP_release(&p->zkpx);
    BN_free(p->gk);
}

static void YAK_CTX_init(YAK_CTX *ctx, const char *name,
                         const char *peer_name, const BIGNUM *p,
                         const EC_POINT *g, const BIGNUM *q,
                         const BIGNUM *secret)
{
    ctx->p.name = OPENSSL_strdup(name);
    ctx->p.peer_name = OPENSSL_strdup(peer_name);
    ctx->p.p = BN_dup(p);
    ctx->p.g = BN_dup(g);
    ctx->p.q = BN_dup(q);
    ctx->secret = BN_dup(secret);
    
    ctx->xa = BN_new();
    ctx->key = BN_new();
    ctx->ctx = BN_CTX_new();
}

static void YAK_CTX_release(YAK_CTX *ctx)
{
    BN_CTX_free(ctx->ctx);
    BN_clear_free(ctx->key);
    BN_clear_free(ctx->xb);
    BN_clear_free(ctx->xa);
    
    BN_free(ctx->p.gxd);
    BN_free(ctx->p.gxc);
    
    BN_clear_free(ctx->secret);
    BN_free(ctx->p.q);
    BN_free(ctx->p.g);
    BN_free(ctx->p.p);
    OPENSSL_free(ctx->p.peer_name);
    OPENSSL_free(ctx->p.name);
    
    memset(ctx, '\0', sizeof *ctx);
}

YAK_CTX *YAK_CTX_new(const char *name, const char *peer_name,
                     const BIGNUM *p, const EC_POINT *g, const BIGNUM *q,
                     const BIGNUM *secret)
{
    YAK_CTX *ctx = OPENSSL_malloc(sizeof *ctx);
    
    YAK_CTX_init(ctx, name, peer_name, p, g, q, secret);
    
    return ctx;
}

void YAK_CTX_free(YAK_CTX *ctx)
{
    YAK_CTX_release(ctx);
    OPENSSL_free(ctx);
}

static void hashlength(SHA_CTX *sha, size_t l)
{
    unsigned char b[2];
    
    OPENSSL_assert(l <= 0xffff);
    b[0] = l >> 8;
    b[1] = l&0xff;
    SHA1_Update(sha, b, 2);
}

static void hashstring(SHA_CTX *sha, const char *string)
{
    size_t l = strlen(string);
    
    hashlength(sha, l);
    SHA1_Update(sha, string, l);
}

static void hashbn(SHA_CTX *sha, const BIGNUM *bn)
{
    size_t l = BN_num_bytes(bn);
    unsigned char *bin = OPENSSL_malloc(l);
    
    hashlength(sha, l);
    BN_bn2bin(bn, bin);
    SHA1_Update(sha, bin, l);
    OPENSSL_free(bin);
}

static void hashpoint(const *EC_GROUP group, SHA_CTX *sha, const EC_POINT *point)
{
    BIGNUM *bn = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    
    //Convert EC_POINT to number
    EC_POINT_point2bn(group, point, POINT_CONVERSION_UNCOMPRESSED, bn, ctx)
    
    //Get size of EC_POINT
    size_t l = BN_num_bytes(bn);
    unsigned char *bin = OPENSSL_malloc(l);
    
    hashlength(sha, l);
    BN_bn2bin(bn, bin);
    SHA1_Update(sha, bin, l);
    OPENSSL_free(bin);
}

/* h=hash(g, g^r, g^x, name) */
static void zkp_hash(BIGNUM *h, const BIGNUM *zkpg, const YAK_STEP_PART *p,
                     const char *proof_name)
{
    unsigned char md[SHA_DIGEST_LENGTH];
    SHA_CTX sha;
    
    /*
     * XXX: hash should not allow moving of the boundaries - Java code
     * is flawed in this respect. Length encoding seems simplest.
     */
    SHA1_Init(&sha);
    hashbn(&sha, zkpg);
    OPENSSL_assert(!BN_is_zero(p->zkpx.gr));
    hashpoint(&sha, p->zkpx.gr);
    hashpoint(&sha, p->gk);
    hashstring(&sha, proof_name);
    SHA1_Final(md, &sha);
    BN_bin2bn(md, SHA_DIGEST_LENGTH, h);
}

/*
 * Prove knowledge of x
 * Note that p->gx has already been calculated
 */
static void generate_zkp(YAK_STEP_PART *p, const BIGNUM *x,
                         const BIGNUM *zkpg, YAK_CTX *ctx)
{
    BIGNUM *r = BN_new();
    BIGNUM *h = BN_new();
    BIGNUM *t = BN_new();
    
    /*
     * r in [0,q)
     * XXX: Java chooses r in [0, 2^160) - i.e. distribution not uniform
     */
    BN_rand_range(r, ctx->p.q);
    /* g^r */
    BN_mod_exp(p->zkpx.gr, zkpg, r, ctx->p.p, ctx->ctx);
    
    /* h=hash... */
    zkp_hash(h, zkpg, p, ctx->p.name);
    
    /* b = r - x*h */
    BN_mod_mul(t, x, h, ctx->p.q, ctx->ctx);
    BN_mod_sub(p->zkpx.b, r, t, ctx->p.q, ctx->ctx);
    
    /* cleanup */
    BN_free(t);
    BN_free(h);
    BN_free(r);
}

static int verify_zkp(EC_GROUP group, const YAK_STEP_PART *p, const BIGNUM *zkpg,
                      YAK_CTX *ctx)
{
    BIGNUM *h = BN_new();
    BIGNUM *t1 = BN_new();
    EC_POINT *t1 = EC_POINT_new(group);
    EC_POINT *t2 = EC_POINT_new(group);
    EC_POINT *t3 = EC_POINT_new(group);
    int ret = 0;
    
    zkp_hash(h, zkpg, p, ctx->p.peer_name);
    
    /* t1 = g^b */
    EC_POINT_mul(group, t1, NULL, p->zkpx.b, zkpg, ctx);
    
    //BN_mod_exp(t1, zkpg, p->zkpx.b, ctx->p.p, ctx->ctx);
    /* t2 = (g^x)^h = g^{hx} */
    EC_POINT_mul(group, t2, NULL, p->gk, h, ctx);
    
    
    //BN_mod_exp(t2, p->gx, h, ctx->p.p, ctx->ctx);
    /* t3 = t1 * t2 = g^{hx} * g^b = g^{hx+b} = g^r (allegedly) */
    EC_POINT_add(group, t3, t1, t2, ctx);
    
    /* verify t3 == g^r */
    if(EC_POINT_cmp(group, t3, p->zkpx.gr, ctx) == 0)
        ret = 1;
    else
        YAKerr(YAK_F_VERIFY_ZKP, YAK_R_ZKP_VERIFY_FAILED);
    
    /* cleanup */
    BN_free(t3);
    BN_free(t2);
    BN_free(t1);
    BN_free(h);
    
    return ret;
}

static void generate_step_part(YAK_STEP_PART *p, const BIGNUM *x,
                               const BIGNUM *g, YAK_CTX *ctx)
{
    BN_mod_exp(p->gx, g, x, ctx->p.p, ctx->ctx);
    generate_zkp(p, x, g, ctx);
}

/* Generate each party's random numbers. xa is in [0, q), xb is in [1, q). */
static void genrand(YAK_CTX *ctx)
{
    BIGNUM *qm1;
    
    /* xa in [0, q) */
    BN_rand_range(ctx->xa, ctx->p.q);
    
    /* q-1 */
    qm1 = BN_new();
    BN_copy(qm1, ctx->p.q);
    BN_sub_word(qm1, 1);
    
    /* ... and xb in [0, q-1) */
    BN_rand_range(ctx->xb, qm1);
    /* [1, q) */
    BN_add_word(ctx->xb, 1);
    
    /* cleanup */
    BN_free(qm1);
}

/* g^x is a legal value */
static int is_legal(const BIGNUM *gx, const YAK_CTX *ctx)
{
    BIGNUM *t;
    int res;
    
    if(BN_is_negative(gx) || BN_is_zero(gx) || BN_cmp(gx, ctx->p.p) >= 0)
        return 0;
    
    t = BN_new();
    BN_mod_exp(t, gx, ctx->p.q, ctx->p.p, ctx->ctx);
    res = BN_is_one(t);
    BN_free(t);
    
    return res;
}


/* gx = g^{xc + xa + xb} * xd * s */
static int compute_key(YAK_CTX *ctx, const BIGNUM *gx)
{
    BIGNUM *t1 = BN_new();
    BIGNUM *t2 = BN_new();
    BIGNUM *t3 = BN_new();
    
    /*
     * K = (gx/g^{xb * xd * s})^{xb}
     *   = (g^{(xc + xa + xb) * xd * s - xb * xd *s})^{xb}
     *   = (g^{(xa + xc) * xd * s})^{xb}
     *   = g^{(xa + xc) * xb * xd * s}
     * [which is the same regardless of who calculates it]
     */
    
    /* t1 = (g^{xd})^{xb} = g^{xb * xd} */
    BN_mod_exp(t1, ctx->p.gxd, ctx->xb, ctx->p.p, ctx->ctx);
    /* t2 = -s = q-s */
    BN_sub(t2, ctx->p.q, ctx->secret);
    /* t3 = t1^t2 = g^{-xb * xd * s} */
    BN_mod_exp(t3, t1, t2, ctx->p.p, ctx->ctx);
    /* t1 = gx * t3 = X/g^{xb * xd * s} */
    BN_mod_mul(t1, gx, t3, ctx->p.p, ctx->ctx);
    /* K = t1^{xb} */
    BN_mod_exp(ctx->key, t1, ctx->xb, ctx->p.p, ctx->ctx);
    
    /* cleanup */
    BN_free(t3);
    BN_free(t2);
    BN_free(t1);
    
    return 1;
}


static void quickhashbn(unsigned char *md, const BIGNUM *bn)
{
    SHA_CTX sha;
    
    SHA1_Init(&sha);
    hashbn(&sha, bn);
    SHA1_Final(md, &sha);
}


const BIGNUM *YAK_get_shared_key(YAK_CTX *ctx)
{
    return ctx->key;
}

