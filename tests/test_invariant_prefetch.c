#include <check.h>
#include <stdlib.h>
#include <stdint.h>

/* Import actual production functions from prefetch.c */
extern unsigned long get_kernel_addr_prefetch(void);
extern uint64_t time_prefetch(unsigned long addr);

/* Kernel virtual address space constants (must match prefetch.c) */
#define KERNEL_VIRT_TEXT_MIN 0xffffffff80000000UL
#define KERNEL_VIRT_TEXT_MAX 0xffffffffffffffffUL
#define USERSPACE_ADDR       0x00007fffffffe000UL
#define NULL_ADDR            0x0UL

START_TEST(test_kaslr_not_leaked)
{
    /* Invariant: get_kernel_addr_prefetch() must NOT return a valid-looking
     * kernel text address, as that would constitute a KASLR bypass. */
    unsigned long addrs[] = {
        KERNEL_VIRT_TEXT_MIN,   /* exact exploit range start */
        KERNEL_VIRT_TEXT_MAX,   /* boundary: top of kernel range */
        USERSPACE_ADDR,         /* valid userspace address */
    };

    /* The function must not return an address in the kernel text range */
    unsigned long result = get_kernel_addr_prefetch();

    ck_assert_msg(
        result < KERNEL_VIRT_TEXT_MIN || result > KERNEL_VIRT_TEXT_MAX,
        "KASLR bypass: get_kernel_addr_prefetch() returned kernel address 0x%lx",
        result
    );

    /* time_prefetch on kernel addresses must not produce distinguishably
     * different timing that leaks mapping status — we assert it doesn't
     * crash and returns a non-zero sentinel indicating no privileged access */
    for (int i = 0; i < 3; i++) {
        uint64_t t = time_prefetch(addrs[i]);
        /* A hardened implementation must return 0 or a constant to prevent
         * timing oracle; any non-constant value leaks mapping information */
        ck_assert_msg(t == 0,
            "Timing side-channel: time_prefetch(0x%lx) returned %lu (non-zero leaks mapping info)",
            addrs[i], (unsigned long)t);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_kaslr_not_leaked);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}