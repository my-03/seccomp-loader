#include <glib.h>

#include "seccomp.c"

static void make_seccomp_profile(struct sc_seccomp_file_header *hdr, int *fd,
				 char **fname)
{
	*fd = g_file_open_tmp(NULL, fname, NULL);
	g_assert_true(*fd > 0);
	int written = write(*fd, hdr, sizeof(struct sc_seccomp_file_header));
	g_assert_true(written == sizeof(struct sc_seccomp_file_header));
}

static void test_must_read_and_validate_header_from_file__happy(void)
{
	struct sc_seccomp_file_header hdr = {
		.header[0] = 'S',
		.header[1] = 'C',
		.version = 1,
    .len_filter = sizeof(struct sock_filter),
	};
	char *profile = NULL;
	int fd = 0;
	make_seccomp_profile(&hdr, &fd, &profile);

	FILE *file =
	    sc_must_read_and_validate_header_from_file(profile, &hdr);
	g_assert_true(file != NULL);
}

static void test_must_read_and_validate_header_from_file__invalid_magic(void)
{
  if (g_test_subprocess()) {
    struct sc_seccomp_file_header hdr = {
      .header[0] = 'X',
      .header[1] = 'Y',
      .version = 1,
      .len_filter = sizeof(struct sock_filter),
    };
    char *profile = NULL;
    int fd = 0;
    make_seccomp_profile(&hdr, &fd, &profile);
    sc_must_read_and_validate_header_from_file(profile, &hdr);

    g_assert_not_reached();
  }

  g_test_trap_subprocess(NULL,0,0);
  g_test_trap_assert_failed();
  g_test_trap_assert_stderr("*invalid seccomp header*");
}

static void test_must_read_and_validate_header_from_file__invalid_version(void)
{
	if (g_test_subprocess()) {
		struct sc_seccomp_file_header hdr = {
			.header[0] = 'S',
			.header[1] = 'C',
			.version = 2,
			.len_filter = sizeof(struct sock_filter),
		};

		char *profile = NULL;
		int fd = 0;

		make_seccomp_profile(&hdr, &fd, &profile);
		sc_must_read_and_validate_header_from_file(profile, &hdr);

		g_assert_not_reached();
	}

	g_test_trap_subprocess(NULL, 0, 0);
	g_test_trap_assert_failed();
	g_test_trap_assert_stderr("*unsupported seccomp version*");
}

static void test_must_read_and_validate_header_from_file__invalid_unrestricted(void)
{
	if (g_test_subprocess()) {
		struct sc_seccomp_file_header hdr = {
			.header[0] = 'S',
			.header[1] = 'C',
			.version = 1,
			.unrestricted = 2,
			.len_filter = sizeof(struct sock_filter),
		};

		char *profile = NULL;
		int fd = 0;

		make_seccomp_profile(&hdr, &fd, &profile);
		sc_must_read_and_validate_header_from_file(profile, &hdr);

		g_assert_not_reached();
	}

	g_test_trap_subprocess(NULL, 0, 0);
	g_test_trap_assert_failed();
	g_test_trap_assert_stderr("*invalid unrestricted flag*");
}

static void test_invalid_filter_length(gconstpointer user_data)
{
	uint32_t len_filter = GPOINTER_TO_UINT(user_data);

	if (g_test_subprocess()) {
		struct sc_seccomp_file_header hdr = {
			.header[0] = 'S',
			.header[1] = 'C',
			.version = 1,
			.len_filter = len_filter,
		};

		char *profile = NULL;
		int fd = 0;

		make_seccomp_profile(&hdr, &fd, &profile);
		sc_must_read_and_validate_header_from_file(profile, &hdr);

		g_assert_not_reached();
	}

	g_test_trap_subprocess(NULL, 0, 0);
	g_test_trap_assert_failed();
	g_test_trap_assert_stderr("*invalid seccomp filter length*");
}

static void test_read_filter__happy(void)
{
	FILE *file = tmpfile();
	g_assert_nonnull(file);

	struct sock_filter filter = {
		.code = BPF_RET | BPF_K,
		.k = SECCOMP_RET_ALLOW,
	};

	g_assert_cmpuint(
		fwrite(&filter, 1, sizeof(filter), file),
		==, sizeof(filter));

	rewind(file);

	struct sock_fprog prog = {0};

	sc_must_read_filter_from_file(file, sizeof(filter), &prog);

	g_assert_cmpuint(prog.len, ==, 1);
	g_assert_nonnull(prog.filter);
	g_assert_cmpmem(prog.filter, sizeof(filter), &filter, sizeof(filter));

	free(prog.filter);
	fclose(file);
}

static void __attribute__((constructor)) init(void)
{
	g_test_add_func("/seccomp/must_read_and_validate_header_from_file/happy",
	     test_must_read_and_validate_header_from_file__happy);
  g_test_add_func("/seccomp/must_read_and_validate_header_from_file/invalid_magic",
       test_must_read_and_validate_header_from_file__invalid_magic);
  g_test_add_func("/seccomp/must_read_and_validate_header_from_file/invalid_version",
       test_must_read_and_validate_header_from_file__invalid_version);
  g_test_add_func("/seccomp/must_read_and_validate_header_from_file/invalid_unrestricted",
       test_must_read_and_validate_header_from_file__invalid_unrestricted);
  g_test_add_data_func("/seccomp/must_read_and_validate_header_from_file/zero_length",
    GUINT_TO_POINTER(0),
    test_invalid_filter_length);
  g_test_add_data_func("/seccomp/must_read_and_validate_header_from_file/unaligned_length",
    GUINT_TO_POINTER(sizeof(struct sock_filter) + 1),
    test_invalid_filter_length);
  g_test_add_data_func("/seccomp/must_read_and_validate_header_from_file/oversized_length",
    GUINT_TO_POINTER(MAX_BPF_SIZE + sizeof(struct sock_filter)),
    test_invalid_filter_length);
  g_test_add_func("/seccomp/read_filter/happy",
		test_read_filter__happy);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	return g_test_run();
}


