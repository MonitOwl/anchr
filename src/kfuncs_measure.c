#include "anchr_common.h"
#include "anchr_kfuncs.h"
#include "anchr_container.h"
#include "anchr_merkle.h"
#include "anchr_kfunc_buffer.h"

/*
 * anchr_measurement_extend - Record a bounded measurement request
 * @data: Pointer-free request buffer
 * @data__sz: Verifier-checked buffer size (must match the request structure)
 *
 * Snapshot and validate every field before logging, hashing, or sleeping.
 * Returns: 0 on success, negative error code on failure.
 */

__bpf_kfunc_start_defs();

__bpf_kfunc int anchr_measurement_extend(const void *data, u32 data__sz)
{
    struct anchr_measurement_request request;
    struct container_node *container;
    char concat_data[ANCHR_EVENT_DATA_SIZE + ANCHR_DEPENDENCIES_SIZE];
    const char *effective_ns;
    size_t total_len;
    u8 hash_value[SHA256_DIGEST_SIZE];
    int ret;

    ret = anchr_prepare_measurement(data, data__sz, &request,
                                     concat_data, sizeof(concat_data), &total_len);
    if (ret)
        return ret;

    ret = calculate_sha256_hash(concat_data, total_len, hash_value);
    if (ret)
        return ret;

    effective_ns = request.namespace_id[0] != '\0' ? request.namespace_id : "default";
    ret = anchr_commit_get_error();
    if (ret)
        return ret;
    container = find_container_by_id(effective_ns);
    if (!container)
    {
        container = create_container_node(effective_ns);
        if (IS_ERR(container))
            return PTR_ERR(container);
    }

    ret = add_container_measurement(container, request.event_name,
                                    request.additional_data, request.dependencies,
                                    hash_value, GFP_KERNEL);
    anchr_put_container(container);

    return ret == 1 ? 0 : ret;
}

/*
 * anchr_tpm_get_pcr_value - BPF kfunc to retrieve TPM PCR value or simulation
 * @pcr_buf: Output buffer to store PCR value string (minimum 80 bytes)
 * @pcr_buf__sz: Size of output buffer in bytes
 * Output format:
 * - Real TPM: "PCR23_REAL:abc123def456..."
 * - Simulation: "PCR23_MEASUREMENTS_N_HASH_SIMULATION"
 * - Atomic context: "PCR23_MEASUREMENTS_N_ATOMIC_CONTEXT"
 *
 * Returns: 0 on success, negative error code on failure
 */
__bpf_kfunc int anchr_tpm_get_pcr_value(char *pcr_buf, u32 pcr_buf__sz)
{
    struct tpm_chip *chip;
    struct tpm_digest digest[1];
    int ret = 0;
    bool can_sleep = !in_atomic() && !irqs_disabled();

    if (!pcr_buf)
    {
        printk(KERN_ERR "anchr: pcr_buf is null\n");
        return -EINVAL;
    }

    if (pcr_buf__sz < ANCHR_PCR_BUFFER_SIZE)
    {
        printk(KERN_ERR "anchr: pcr_buf__sz too small: %u (minimum 80)\n",
               pcr_buf__sz);
        return -EINVAL;
    }

    if (!can_sleep)
    {
        snprintf(pcr_buf, pcr_buf__sz, "PCR%d_ATOMIC_CONTEXT",
                 anchr_tpm_pcr_index);
        printk(KERN_INFO "Called from atomic context, using simulation\n");
        return 0;
    }

    mutex_lock(&anchr_commit_mutex);
    ret = anchr_commit_check_locked();
    if (ret) {
        mutex_unlock(&anchr_commit_mutex);
        return ret;
    }
    mutex_lock(&anchr_tpm_mutex);

    chip = tpm_default_chip();
    if (!chip)
    {
        if (anchr_commit_requires_hardware_locked()) {
            anchr_commit_fail_locked(-ENODEV);
            mutex_unlock(&anchr_tpm_mutex);
            mutex_unlock(&anchr_commit_mutex);
            return -ENODEV;
        }
        mutex_unlock(&anchr_tpm_mutex);
        mutex_unlock(&anchr_commit_mutex);
        snprintf(pcr_buf, pcr_buf__sz, "PCR%d_HASH_SIMULATION",
                 anchr_tpm_pcr_index);
        printk(KERN_INFO "TPM not available, using simulation\n");
        return 0;
    }
    if (!anchr_commit_hardware_allowed_locked()) {
        anchr_commit_fail_locked(-EIO);
        put_device(&chip->dev);
        mutex_unlock(&anchr_tpm_mutex);
        mutex_unlock(&anchr_commit_mutex);
        return -EIO;
    }

    memset(digest, 0, sizeof(digest));
    digest[0].alg_id = TPM_ALG_SHA256;

    ret = tpm_pcr_read(chip, anchr_tpm_pcr_index, digest);
    put_device(&chip->dev);

    mutex_unlock(&anchr_tpm_mutex);
    mutex_unlock(&anchr_commit_mutex);

    if (ret != 0)
    {
        snprintf(pcr_buf, pcr_buf__sz, "PCR%d_HASH_SIMULATION",
                 anchr_tpm_pcr_index);
        printk(KERN_WARNING "TPM PCR read failed (%d), using simulation\n", ret);
        return ret > 0 ? -EIO : ret;
    }

    snprintf(pcr_buf, pcr_buf__sz, "PCR%d_REAL:", anchr_tpm_pcr_index);
    for (int i = 0; i < SHA256_DIGEST_SIZE && strlen(pcr_buf) < pcr_buf__sz - 3; i++)
    {
        snprintf(pcr_buf + strlen(pcr_buf), pcr_buf__sz - strlen(pcr_buf),
                 "%02x", digest[0].digest[i]);
    }

    return 0;
}

/*
 * anchr_tpm_is_available - BPF kfunc to check TPM hardware availability
 *
 * Attempts to acquire the default TPM chip to test if TPM hardware is available
 * and accessible. This is a lightweight check that doesn't perform any operations
 * on the TPM, just verifies that the chip can be obtained.
 *
 * Safe to call from any context as it only performs chip acquisition/release.
 *
 * Returns: 1 if TPM is available, 0 if not available
 */
__bpf_kfunc int anchr_tpm_is_available(void)
{
    return anchr_tpm_available();
}

__bpf_kfunc_end_defs();
