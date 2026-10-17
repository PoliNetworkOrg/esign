/*
 * p11check drives a CIE PKCS#11 module the way a native application would, to check the simulator against the
 * official middleware (and OpenCIE) without any Go code in the path.
 *
 *   p11check <module> probe                 slots, token, and what C_OpenSession answers
 *   p11check <module> pair <symbol> <pin>   the module's pairing entry point, e.g. AbilitaCIE or cie_enable
 *   p11check <module> sign <login PIN> <SHA-256 hex> <signature out> <certificate out>
 *
 * Build: cc -I<miekg/pkcs11 module dir> -o p11check p11check.c -ldl
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11go.h"

typedef CK_RV (*progress_fn)(const int progress, const char *message);
typedef CK_RV (*completed_fn)(const char *pan, const char *name, const char *serial);
typedef CK_RV (*pair_fn)(const char *pan, const char *pin, int *attempts, progress_fn, completed_fn);

static CK_RV progress(const int p, const char *m) {
	fprintf(stderr, "    pairing %3d%% %s\n", p, m ? m : "");
	return CKR_OK;
}

static CK_RV completed(const char *pan, const char *name, const char *serial) {
	printf("    paired card: PAN %s, holder %s, serial %s\n", pan, name, serial);
	return CKR_OK;
}

static CK_FUNCTION_LIST_PTR p11;

static void check(const char *what, CK_RV rv) {
	if (rv != CKR_OK) {
		printf("%s: rv=0x%lx\n", what, (unsigned long)rv);
		exit(2);
	}
}

static CK_OBJECT_HANDLE find(CK_SESSION_HANDLE s, CK_OBJECT_CLASS cls) {
	CK_ATTRIBUTE t = {CKA_CLASS, &cls, sizeof cls};
	CK_OBJECT_HANDLE h = 0;
	CK_ULONG n = 0;
	check("C_FindObjectsInit", p11->C_FindObjectsInit(s, &t, 1));
	check("C_FindObjects", p11->C_FindObjects(s, &h, 1, &n));
	p11->C_FindObjectsFinal(s);
	if (n == 0) {
		printf("no object of class %lu\n", (unsigned long)cls);
		exit(2);
	}
	return h;
}

static void write_file(const char *path, const void *data, size_t len) {
	FILE *f = fopen(path, "wb");
	if (!f || fwrite(data, 1, len, f) != len) {
		perror(path);
		exit(2);
	}
	fclose(f);
}

static CK_SLOT_ID first_slot(void) {
	CK_SLOT_ID slots[8];
	CK_ULONG n = 8;
	check("C_GetSlotList", p11->C_GetSlotList(CK_TRUE, slots, &n));
	if (n == 0) {
		printf("no token present\n");
		exit(2);
	}
	return slots[0];
}

int main(int argc, char **argv) {
	if (argc < 3) {
		fprintf(stderr, "usage: p11check <module> probe|pair|sign ...\n");
		return 1;
	}
	void *lib = dlopen(argv[1], RTLD_NOW);
	if (!lib) {
		fprintf(stderr, "dlopen: %s\n", dlerror());
		return 1;
	}
	const char *cmd = argv[2];

	if (strcmp(cmd, "pair") == 0 && argc == 5) {
		pair_fn pair = (pair_fn)dlsym(lib, argv[3]);
		if (!pair) {
			printf("%s not exported\n", argv[3]);
			return 2;
		}
		int attempts = -1;
		CK_RV rv = pair(NULL, argv[4], &attempts, progress, completed);
		printf("%s: rv=0x%lx attempts=%d\n", argv[3], (unsigned long)rv, attempts);
		return 0;
	}

	CK_RV (*get)(CK_FUNCTION_LIST_PTR_PTR) = (CK_RV(*)(CK_FUNCTION_LIST_PTR_PTR))dlsym(lib, "C_GetFunctionList");
	if (!get) {
		fprintf(stderr, "C_GetFunctionList not exported\n");
		return 1;
	}
	check("C_GetFunctionList", get(&p11));
	check("C_Initialize", p11->C_Initialize(NULL));

	if (strcmp(cmd, "probe") == 0) {
		CK_SLOT_ID slots[8];
		CK_ULONG all = 8, present = 8;
		check("C_GetSlotList(all)", p11->C_GetSlotList(CK_FALSE, slots, &all));
		check("C_GetSlotList(present)", p11->C_GetSlotList(CK_TRUE, slots, &present));
		printf("slots: %lu, with token: %lu\n", (unsigned long)all, (unsigned long)present);
		if (present > 0) {
			CK_TOKEN_INFO ti;
			CK_RV rv = p11->C_GetTokenInfo(slots[0], &ti);
			printf("C_GetTokenInfo: rv=0x%lx label=\"%.32s\" model=\"%.16s\" flags=0x%lx\n", (unsigned long)rv, ti.label,
			       ti.model, (unsigned long)ti.flags);
			CK_SESSION_HANDLE s;
			rv = p11->C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL, NULL, &s);
			printf("C_OpenSession: rv=0x%lx\n", (unsigned long)rv);
			if (rv == CKR_OK) {
				CK_OBJECT_CLASS cls = CKO_CERTIFICATE;
				CK_ATTRIBUTE t = {CKA_CLASS, &cls, sizeof cls};
				CK_OBJECT_HANDLE h[4];
				CK_ULONG n = 0;
				p11->C_FindObjectsInit(s, &t, 1);
				p11->C_FindObjects(s, h, 4, &n);
				p11->C_FindObjectsFinal(s);
				printf("certificates: %lu\n", (unsigned long)n);
				p11->C_CloseSession(s);
			}
		}
		p11->C_Finalize(NULL);
		return 0;
	}

	if (strcmp(cmd, "sign") == 0 && argc == 7) {
		const char *hex = argv[4];
		if (strlen(hex) != 64) {
			fprintf(stderr, "digest must be 32 bytes in hex\n");
			return 1;
		}
		/* The 51-byte SHA-256 DigestInfo for CKM_RSA_PKCS. */
		unsigned char di[51] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
		for (int i = 0; i < 32; i++)
			sscanf(hex + 2 * i, "%2hhx", &di[19 + i]);

		CK_SESSION_HANDLE s;
		check("C_OpenSession", p11->C_OpenSession(first_slot(), CKF_SERIAL_SESSION, NULL, NULL, &s));
		CK_OBJECT_HANDLE cert = find(s, CKO_CERTIFICATE);
		CK_ATTRIBUTE v = {CKA_VALUE, NULL, 0};
		check("C_GetAttributeValue(size)", p11->C_GetAttributeValue(s, cert, &v, 1));
		v.pValue = malloc(v.ulValueLen);
		check("C_GetAttributeValue", p11->C_GetAttributeValue(s, cert, &v, 1));
		write_file(argv[6], v.pValue, v.ulValueLen);
		printf("certificate object: %lu bytes (readable before C_Login)\n", (unsigned long)v.ulValueLen);

		CK_RV rv = p11->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)argv[3], strlen(argv[3]));
		printf("C_Login(%zu digits): rv=0x%lx\n", strlen(argv[3]), (unsigned long)rv);
		if (rv != CKR_OK)
			return 3;
		CK_OBJECT_HANDLE key = find(s, CKO_PRIVATE_KEY);
		CK_MECHANISM mech = {CKM_RSA_PKCS, NULL, 0};
		check("C_SignInit", p11->C_SignInit(s, &mech, key));
		unsigned char sig[512];
		CK_ULONG sigLen = sizeof sig;
		check("C_Sign", p11->C_Sign(s, di, sizeof di, sig, &sigLen));
		write_file(argv[5], sig, sigLen);
		printf("C_Sign(CKM_RSA_PKCS, DigestInfo): %lu-byte signature\n", (unsigned long)sigLen);
		p11->C_Logout(s);
		p11->C_CloseSession(s);
		p11->C_Finalize(NULL);
		return 0;
	}
	fprintf(stderr, "bad arguments\n");
	return 1;
}
