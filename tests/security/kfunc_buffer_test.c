#include <assert.h>
#include <limits.h>
#include <stdio.h>

#include "anchr_kfunc_buffer.h"

static void test_string_bounds(void)
{
    char dest[ANCHR_NAMESPACE_SIZE];
    char unterminated[ANCHR_NAMESPACE_SIZE];
    char one_byte[] = {'x'};
    char empty[] = "";
    char valid[] = "container";

    memset(unterminated, 'x', sizeof(unterminated));
    assert(anchr_copy_kfunc_string(NULL, sizeof(dest), valid, sizeof(valid), false) == -EINVAL);
    assert(anchr_copy_kfunc_string(dest, 0, valid, sizeof(valid), false) == -EINVAL);
    assert(anchr_copy_kfunc_string(dest, sizeof(dest), NULL, 1, false) == -EINVAL);
    assert(anchr_copy_kfunc_string(dest, sizeof(dest), one_byte, 0, false) == -EINVAL);
    assert(anchr_copy_kfunc_string(dest, sizeof(dest), one_byte, UINT_MAX, false) == -EINVAL);
    assert(anchr_copy_kfunc_string(dest, sizeof(dest), one_byte, sizeof(one_byte), false) == -EINVAL);
    assert(anchr_copy_kfunc_string(dest, sizeof(dest), empty, sizeof(empty), false) == -EINVAL);
    assert(anchr_copy_kfunc_string(dest, sizeof(dest), empty, sizeof(empty), true) == 0);
    assert(anchr_copy_kfunc_string(dest, sizeof(dest), unterminated,
                                   sizeof(unterminated), false) == -EINVAL);
    unterminated[sizeof(unterminated) - 1] = '\0';
    assert(anchr_copy_kfunc_string(dest, sizeof(dest), unterminated,
                                   sizeof(unterminated), false) == 0);
    assert(anchr_copy_kfunc_string(dest, sizeof(dest), valid, sizeof(valid), false) == 0);
    valid[0] = 'X';
    assert(strcmp(dest, "container") == 0);
    assert(anchr_validate_namespace(".") == -EINVAL);
    assert(anchr_validate_namespace(NULL) == -EINVAL);
    assert(anchr_validate_namespace("") == -EINVAL);
    assert(anchr_validate_namespace("..") == -EINVAL);
    assert(anchr_validate_namespace("a/b") == -EINVAL);
    assert(anchr_validate_namespace("container") == 0);
}

static struct anchr_measurement_request valid_request(void)
{
    struct anchr_measurement_request request = {0};

    strcpy(request.event_name, "test");
    strcpy(request.additional_data, "data");
    request.additional_data_len = 4;
    return request;
}

static void test_measurement_bounds(void)
{
    struct anchr_measurement_request request = valid_request();
    struct anchr_measurement_request snapshot;
    char concat[ANCHR_EVENT_DATA_SIZE + ANCHR_DEPENDENCIES_SIZE];
    char one_byte = 0;
    size_t length = 0;

    assert(anchr_prepare_measurement(NULL, sizeof(request), &snapshot,
                                      concat, sizeof(concat), &length) == -EINVAL);
    assert(anchr_prepare_measurement(&one_byte, 0, &snapshot,
                                      concat, sizeof(concat), &length) == -EINVAL);
    assert(anchr_prepare_measurement(&request, sizeof(request), NULL,
                                      concat, sizeof(concat), &length) == -EINVAL);
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      NULL, sizeof(concat), &length) == -EINVAL);
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, sizeof(concat), NULL) == -EINVAL);
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, 0, &length) == -E2BIG);
    assert(anchr_prepare_measurement(&one_byte, 1, &snapshot,
                                      concat, sizeof(concat), &length) == -EINVAL);
    assert(anchr_prepare_measurement(&one_byte, UINT_MAX, &snapshot,
                                      concat, sizeof(concat), &length) == -EINVAL);
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, sizeof(concat), &length) == 0);
    assert(length == 4 && memcmp(concat, "data", length) == 0);
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, 4, &length) == 0);
    request.additional_data[0] = 'X';
    assert(strcmp(snapshot.additional_data, "data") == 0);

    request = valid_request();
    request.additional_data_len = UINT_MAX;
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, sizeof(concat), &length) == -EINVAL);
    request.additional_data_len = ANCHR_EVENT_DATA_SIZE;
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, sizeof(concat), &length) == -EINVAL);

    request = valid_request();
    memset(request.event_name, 'x', sizeof(request.event_name));
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, sizeof(concat), &length) == -EINVAL);
    request = valid_request();
    request.event_name[0] = '\0';
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, sizeof(concat), &length) == -EINVAL);
    request = valid_request();
    memset(request.namespace_id, 'x', sizeof(request.namespace_id));
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, sizeof(concat), &length) == -EINVAL);
    request = valid_request();
    strcpy(request.namespace_id, "..");
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, sizeof(concat), &length) == -EINVAL);
    request = valid_request();
    memset(request.dependencies, 'x', sizeof(request.dependencies));
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, sizeof(concat), &length) == -EINVAL);
    request = valid_request();
    strcpy(request.dependencies, "deps");
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, sizeof(concat), &length) == -EINVAL);
    request.flags = ANCHR_MEASUREMENT_HAS_DEPENDENCIES;
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, sizeof(concat), &length) == 0);
    assert(length == 9 && memcmp(concat, "data deps", length) == 0);
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, 4, &length) == -E2BIG);
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, 8, &length) == -E2BIG);

    request = valid_request();
    request.flags = UINT_MAX;
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, sizeof(concat), &length) == -EINVAL);
    request = valid_request();
    request.additional_data_len = 0;
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, sizeof(concat), &length) == -EINVAL);

    request = valid_request();
    memset(request.additional_data, 'a', sizeof(request.additional_data));
    request.additional_data_len = sizeof(request.additional_data) - 1;
    memset(request.dependencies, 'd', sizeof(request.dependencies) - 1);
    request.flags = ANCHR_MEASUREMENT_HAS_DEPENDENCIES;
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, sizeof(concat), &length) == 0);
    assert(length == 511);
    assert(snapshot.additional_data[255] == '\0');
    assert(concat[255] == ' ');

    request = valid_request();
    request.flags = ANCHR_MEASUREMENT_HAS_DEPENDENCIES;
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, sizeof(concat), &length) == 0);
    assert(length == 5 && memcmp(concat, "data ", length) == 0);

    request.additional_data_len = 0;
    strcpy(request.dependencies, "deps");
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, sizeof(concat), &length) == 0);
    assert(length == 4 && memcmp(concat, "deps", length) == 0);
    assert(snapshot.additional_data[0] == '\0');

    request = valid_request();
    request.additional_data[1] = '\0';
    strcpy(request.namespace_id, "container");
    assert(anchr_prepare_measurement(&request, sizeof(request), &snapshot,
                                      concat, sizeof(concat), &length) == 0);
    assert(length == 4 && memcmp(concat, "d\0ta", length) == 0);
}

int main(void)
{
    test_string_bounds();
    test_measurement_bounds();
    puts("PASS: bounded strings, request snapshots, lengths, and concatenation");
    return 0;
}
