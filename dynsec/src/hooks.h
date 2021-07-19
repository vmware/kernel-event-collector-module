
#pragma once

extern int dynsec_bprm_set_creds(struct linux_binprm *bprm);

extern int dynsec_inode_unlink(struct inode *dir, struct dentry *dentry);

extern int dynsec_inode_rmdir(struct inode *dir, struct dentry *dentry);

extern int dynsec_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
                               struct inode *new_dir, struct dentry *new_dentry);
