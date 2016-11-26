#include"antivirus.h"

static int init_desc(struct hash_desc *desc)
{
	int rc;
	desc->tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_TYPE_DIGEST);
	if (IS_ERR(desc->tfm)) {
		printk("Failed to load %s transform: %ld\n",
				"sha1", PTR_ERR(desc->tfm));
		rc = PTR_ERR(desc->tfm);
		return rc;
	}
	desc->flags = 0;
	rc = crypto_hash_init(desc);
	if (rc)
		crypto_free_hash(desc->tfm);
	return rc;
}


/*
 * Calculate the SHA1 file digest
 */
int calculate_hash(struct file *input_file,char *sha1_hash)
{
	struct hash_desc desc;
	struct scatterlist scatter_list[1];
	loff_t i_size, offset = 0;
	char *file_buf=NULL;
	unsigned char * digest=NULL;
	int rc = 0,i;
	rc = init_desc(&desc);
	digest=kzalloc(crypto_hash_crt(desc.tfm)->digestsize,GFP_KERNEL);
	
	if (rc != 0)
	{
		rc =-1;
		goto out;
	}
	file_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!file_buf) {
		rc = -ENOMEM;
		goto out;
	}
	i_size = i_size_read(input_file->f_path.dentry->d_inode);
	while (offset < i_size) {
		int file_buf_len;

		file_buf_len = kernel_read(input_file, offset, file_buf, PAGE_SIZE);
		if (file_buf_len < 0) {
			rc = file_buf_len;
			break;
		}
		if (file_buf_len == 0)
			break;
		offset +=file_buf_len;
		sg_init_one(scatter_list, file_buf, file_buf_len);

		rc = crypto_hash_update(&desc, scatter_list, file_buf_len);
		if (rc)
			break;
	}
	if (!rc)
		rc = crypto_hash_final(&desc, digest);
	for (i = 0; i < 20; i++) {
		sprintf(&sha1_hash[i*2],"%02x", digest[i]);
	}
		
out:
	crypto_free_hash(desc.tfm);
	if(digest)	
		kfree(digest);
	if(file_buf)	
		kfree(file_buf);
	return rc;
}

/*
* Check whether the sha1sum of the file is present in the  whitelist
*/
bool check_in_whitelist(struct file * input_file,struct file * white_list)
{
	bool in_whitelist=false;
	int size=PAGE_SIZE,file_seek_position=0;
	char *pattern=NULL,*sha1_hash_file=NULL,*whitelist_buffer=NULL,*init_buffer = NULL;
	const char *delimiter="\n";
	loff_t i_size = 0;
	init_buffer = kmalloc(size,GFP_KERNEL);
	
	if(init_buffer == NULL)
		goto out;
		
	init_buffer[0]='\0';
	i_size = i_size_read(file_inode(white_list));
	
	sha1_hash_file=kzalloc(41,GFP_KERNEL);
	if(sha1_hash_file==NULL)
		goto out;	
	sha1_hash_file[0]='\0';

	if(calculate_hash(input_file,sha1_hash_file) < 0)
	{
		goto out;
	}
	
	while(i_size>0)
	{
		if(pattern==NULL)
		{	
			whitelist_buffer=init_buffer;
			read_file(white_list,whitelist_buffer,size);
			file_seek_position += remove_garbage_value(whitelist_buffer,size);
			white_list->f_pos = file_seek_position;
			i_size-=strlen(whitelist_buffer);
			pattern=strsep(&whitelist_buffer,delimiter);
		}
		while(pattern!=NULL)
		{
			if(strcmp(sha1_hash_file,pattern)==0)
			{
				in_whitelist=true;
				goto out;
			}
			pattern=strsep(&whitelist_buffer,delimiter);
			if(pattern==NULL||strlen(pattern)==0)
			{
				pattern=NULL;
			}
		}
	}

out:
	if(init_buffer!=NULL)
		kfree(init_buffer);
	if(sha1_hash_file!=NULL)	
		kfree(sha1_hash_file);	
	return in_whitelist;

}





