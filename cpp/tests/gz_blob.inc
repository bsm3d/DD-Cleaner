// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Test data: a gzip compressed byte blob with its packed and plain sizes, used by the decompression tests.

static const unsigned char GZ_BLOB[] = {31,139,8,0,0,0,0,0,2,255,237,200,65,10,0,16,16,0,192,175,236,227,8,181,69,46,202,235,253,67,51,199,233,53,115,70,187,99,197,153,59,75,116,33,132,16,66,8,33,132,16,66,8,33,132,16,66,8,33,132,16,66,136,255,227,1,6,125,119,43,52,33,0,0};
static const size_t GZ_BLOB_SIZE = 74;
static const size_t GZ_PLAIN_SIZE = 8500;
