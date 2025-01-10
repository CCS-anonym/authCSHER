#pragma once

class DS_performance_metrics
{
public:
    long long push_to_queue = 0;
    long long derive_b_t = 0;
    long long deserialize = 0;
    long long reconstruct = 0;
    long long verify = 0;
    long long square_diff = 0;
    long long derive_kmacs = 0;
    long long deserialize_macs = 0;
    long long wait_for_auxiliary = 0;
    long long total_receive_and_process = 0;
    long long receive_from_aux = 0;
    long long end2end = 0;

    static std::string getHeader();
};
