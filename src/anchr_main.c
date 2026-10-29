#include "anchr_common.h"
#include "anchr_container.h"
#include "anchr_kfuncs.h"
#include "anchr_merkle.h"
#include "anchr_securityfs.h"
#include "anchr_policy.h"

/*
 * anchr_securityfs_init - Initialize SecurityFS interface for anchr
 *
 * Creates the SecurityFS directory and files to expose anchr measurement
 * data to userspace. The interface provides:
 *
 * /sys/kernel/security/anchr/measurements - List of all measurements
 * /sys/kernel/security/anchr/status - Module status and configuration
 *
 * If the "anchr" directory already exists (from previous module load),
 * creates a unique directory name using the current process PID to avoid
 * conflicts: "anchr_<pid>"
 *
 * Files are created with read-only permissions (0444) for security.
 * Proper cleanup on failure ensures no partial state is left behind.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int anchr_securityfs_init(void)
{
    int ret = 0;
    anchr_dir = securityfs_create_dir("anchr", NULL);
    if (IS_ERR(anchr_dir))
    {
        long err = PTR_ERR(anchr_dir);
        if (err == -EEXIST)
        {
            snprintf(anchr_dir_name, sizeof(anchr_dir_name), "anchr_%d", current->pid);
            pr_info("anchr: Directory exists, using unique name: %s\n", anchr_dir_name);
            anchr_dir = securityfs_create_dir(anchr_dir_name, NULL);
            if (IS_ERR(anchr_dir))
            {
                pr_err("anchr: Failed to create unique securityfs directory: %ld\n", PTR_ERR(anchr_dir));
                return PTR_ERR(anchr_dir);
            }
        }
        else
        {
            pr_err("anchr: Failed to create securityfs directory: %ld\n", err);
            return err;
        }
    }

    status_file = securityfs_create_file("status", 0444,
                                         anchr_dir, NULL, &status_fops);
    if (IS_ERR(status_file))
    {
        pr_err("anchr: Failed to create status file: %ld\n", PTR_ERR(status_file));
        securityfs_remove(anchr_dir);
        anchr_dir = NULL;
        return PTR_ERR(status_file);
    }

    merkle_root_history_file = securityfs_create_file("merkle_root_history", 0444,
                                                      anchr_dir, NULL, &merkle_root_history_fops);
    if (IS_ERR(merkle_root_history_file))
    {
        pr_err("anchr: Failed to create merkle_root_history file: %ld\n", PTR_ERR(merkle_root_history_file));
        securityfs_remove(status_file);
        securityfs_remove(anchr_dir);
        status_file = NULL;
        anchr_dir = NULL;
        return PTR_ERR(merkle_root_history_file);
    }

    containers_dir = securityfs_create_dir("namespaces", anchr_dir);
    if (IS_ERR(containers_dir))
    {
        pr_err("anchr: Failed to create namespaces directory: %ld\n", PTR_ERR(containers_dir));
        securityfs_remove(merkle_root_history_file);
        securityfs_remove(status_file);
        securityfs_remove(anchr_dir);
        merkle_root_history_file = NULL;
        status_file = NULL;
        anchr_dir = NULL;
        return PTR_ERR(containers_dir);
    }

    ret = create_global_policy_securityfs(anchr_dir);
    if (ret)
    {
        pr_err("anchr: Failed to create global policy file: %d\n", ret);
        securityfs_remove(containers_dir);
        securityfs_remove(merkle_root_history_file);
        securityfs_remove(status_file);
        securityfs_remove(anchr_dir);
        containers_dir = NULL;
        merkle_root_history_file = NULL;
        status_file = NULL;
        anchr_dir = NULL;
        return ret;
    }

    ret = create_global_policy_changes_securityfs(anchr_dir);
    if (ret)
    {
        pr_err("anchr: Failed to create global policy_changes file: %d\n", ret);
        remove_global_policy_securityfs();
        securityfs_remove(containers_dir);
        securityfs_remove(merkle_root_history_file);
        securityfs_remove(status_file);
        securityfs_remove(anchr_dir);
        containers_dir = NULL;
        merkle_root_history_file = NULL;
        status_file = NULL;
        anchr_dir = NULL;
        return ret;
    }

    pr_info("anchr: SecurityFS interface created at /sys/kernel/security/%s/\n", anchr_dir_name);
    pr_info("anchr: Global policy at /sys/kernel/security/%s/policy\n", anchr_dir_name);
    pr_info("anchr: Global policy changes at /sys/kernel/security/%s/policy_changes\n", anchr_dir_name);
    pr_info("anchr: Namespace tracking enabled at /sys/kernel/security/%s/namespaces/\n", anchr_dir_name);
    return 0;
}

BTF_KFUNCS_START(bpf_kfunc_example_ids_set)
BTF_ID_FLAGS(func, anchr_measurement_extend, KF_SLEEPABLE)
BTF_ID_FLAGS(func, anchr_tpm_get_pcr_value, KF_SLEEPABLE)
BTF_ID_FLAGS(func, anchr_tpm_is_available)
BTF_ID_FLAGS(func, anchr_container_get_or_create, KF_SLEEPABLE)
BTF_ID_FLAGS(func, anchr_merkle_get_root)

BTF_ID_FLAGS(func, anchr_container_get_count)
BTF_ID_FLAGS(func, anchr_container_get_measurement_count)
BTF_ID_FLAGS(func, anchr_container_exists)
BTF_ID_FLAGS(func, anchr_container_get_leaf_hash)

BTF_ID_FLAGS(func, anchr_policy_update_filter_flags, KF_SLEEPABLE)
BTF_ID_FLAGS(func, anchr_policy_update_action_flags, KF_SLEEPABLE)
BTF_ID_FLAGS(func, anchr_policy_update_min_file_size, KF_SLEEPABLE)
BTF_ID_FLAGS(func, anchr_policy_update_log_level, KF_SLEEPABLE)
BTF_ID_FLAGS(func, anchr_policy_get_changes_hash, KF_SLEEPABLE)
BTF_ID_FLAGS(func, anchr_policy_namespace_get_config, KF_SLEEPABLE)
BTF_ID_FLAGS(func, anchr_policy_should_ignore_cgroup, KF_SLEEPABLE)
BTF_ID_FLAGS(func, anchr_policy_should_ignore_path, KF_SLEEPABLE)
BTF_ID_FLAGS(func, anchr_policy_resolve, KF_SLEEPABLE)
BTF_KFUNCS_END(bpf_kfunc_example_ids_set)

const struct btf_kfunc_id_set bpf_kfunc_example_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kfunc_example_ids_set,
};

/*
 * anchr_init - Module initialization function
 *
 * Registers the separate kprobe and shared tracing kfunc sets. The tracing
 * registration also covers tracepoint, raw tracepoint, perf event, and LSM
 * programs. Registering those types separately would duplicate the same
 * kernel kfunc hook and invalidate the module's registration table.
 *
 * Returns: 0 on success, negative error code on registration failure
 */
static int __init anchr_init(void)
{
    int ret;

    printk(KERN_INFO "anchr module initializing...\n");

    if (anchr_tpm_pcr_index < 0 || anchr_tpm_pcr_index > 23)
        return -EINVAL;
    anchr_commit_init();

    ret = anchr_policy_init();
    if (ret)
    {
        pr_err("anchr: Failed to initialize policy subsystem: %d\n", ret);
        return ret;
    }

    ret = anchr_hash_init();
    if (ret)
    {
        pr_err("anchr: Failed to initialize hash subsystem: %d\n", ret);
        goto err_policy;
    }

    ret = anchr_policy_namespace_init();
    if (ret)
    {
        pr_err("anchr: Failed to initialize namespace policy subsystem: %d\n", ret);
        goto err_hash;
    }

    ret = anchr_container_init();
    if (ret)
        goto err_policy_ns;

    memset(&system_merkle_root, 0, sizeof(system_merkle_root));
    spin_lock_init(&system_merkle_root.lock);
    
    system_merkle_root.tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(system_merkle_root.tfm))
    {
        ret = PTR_ERR(system_merkle_root.tfm);
        system_merkle_root.tfm = NULL;
        pr_err("anchr: Failed to allocate tfm for system merkle root: %d\n", ret);
        goto err_containers;
    }
    pr_info("anchr: Merkle tree root initialized\n");

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_example_set);
    if (ret)
    {
        pr_err("anchr: Failed to register BTF kfunc ID set for kprobe: %d\n", ret);
        goto err_merkle_tfm;
    }

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &bpf_kfunc_example_set);
    if (ret)
    {
        pr_err("anchr: Failed to register BTF kfunc ID set for tracing/LSM: %d\n", ret);
        goto err_merkle_tfm;
    }

    ret = anchr_securityfs_init();
    if (ret)
    {
        pr_err("anchr: Failed to initialize SecurityFS interface: %d\n", ret);
        goto err_merkle_tfm;
    }

    printk(KERN_INFO "anchr: Module loaded successfully\n");
    return 0;

err_merkle_tfm:
    if (system_merkle_root.tfm)
    {
        crypto_free_shash(system_merkle_root.tfm);
        system_merkle_root.tfm = NULL;
    }
err_containers:
    anchr_container_cleanup();
err_policy_ns:
    anchr_policy_namespace_cleanup();
err_hash:
    anchr_hash_cleanup();
err_policy:
    anchr_policy_cleanup();
    return ret;
}

/*
 * anchr_exit - Module cleanup function
 *
 * Performs complete cleanup when the module is unloaded:
 * 1. Prints final measurement list for audit purposes
 * 2. Safely deallocates all measurement entries from the list
 * 3. Uses proper locking to prevent race conditions during cleanup
 *
 * The function ensures all allocated memory is freed and provides
 * a final summary of measurement activity before module removal.
 * No explicit BTF kfunc unregistration needed as the kernel handles
 * this automatically when the module is unloaded.
 */
static void __exit anchr_exit(void)
{
    printk(KERN_INFO "anchr module unloading...\n");

    /* Clean up container tracking structures FIRST (includes per-container securityfs) */
    cleanup_all_containers();
    anchr_container_cleanup();
    cleanup_merkle_root_history();

    if (system_merkle_root.tfm)
        crypto_free_shash(system_merkle_root.tfm);

    /* Now clean up main securityfs interface (after containers are gone) */
    anchr_securityfs_cleanup();

    /* Clean up policy subsystem */
    anchr_policy_namespace_cleanup();
    anchr_policy_cleanup();



    anchr_hash_cleanup();

    printk(KERN_INFO "Container tracking: %d containers tracked\n",
           atomic_read(&container_count));
    printk(KERN_INFO "anchr module unloaded.\n");
}

module_init(anchr_init);
module_exit(anchr_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MonitOwl");
MODULE_DESCRIPTION("anchr: eBPF-enhanced Integrity Measurement Architecture with TPM integration");
MODULE_VERSION("1.0");

MODULE_IMPORT_NS("BPF_INTERNAL");
