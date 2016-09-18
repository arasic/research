CREATE TABLE test.traffic (
    uuid uuid PRIMARY KEY,
    data_size bigint,
    dst_ip inet,
    dst_mac_addr text,
    dst_port int,
    insertion_time timestamp,
    packets bigint,
    protocol int,
    src_ip inet,
    src_mac_addr text,
    src_port int
);

