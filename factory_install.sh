mount /dev/sda1 /mnt/stateful_partition
mkdir -p /usr/local/bin/rmasmoke
cp /mnt/stateful_partition/usrlocal/rmasmoke /usr/local/bin/rmasmoke
echo "Run RMASmoke to disable write-protect"
bash