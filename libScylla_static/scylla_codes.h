#pragma once

/* Scylla Dll API error IDs */
const int SCY_ERROR_SUCCESS = 0;
const int SCY_ERROR_PROCOPEN = -1;
const int SCY_ERROR_IATWRITE = -2;
const int SCY_ERROR_IATSEARCH = -3;
const int SCY_ERROR_IATNOTFOUND = -4;
const int SCY_ERROR_PIDNOTFOUND = -5;

enum class scylla_status
{
    success = SCY_ERROR_SUCCESS,
    process_open_failed = SCY_ERROR_PROCOPEN,
    iat_write_failed = SCY_ERROR_IATWRITE,
    iat_search_failed = SCY_ERROR_IATSEARCH,
    iat_not_found = SCY_ERROR_IATNOTFOUND,
    pid_not_found = SCY_ERROR_PIDNOTFOUND
};
