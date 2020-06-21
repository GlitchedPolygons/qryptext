/*
   Copyright 2020 Raphael Beck

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <setjmp.h>
#include <cmocka.h>
#include "qryptext/util.h"
#include "qryptext/sign.h"
#include "qryptext/verify.h"
#include "qryptext/encrypt.h"
#include "qryptext/decrypt.h"
#include "qryptext/constants.h"

/* A test case that does nothing and succeeds. */
static void null_test_success(void** state)
{
    (void)state;
}

// --------------------------------------------------------------------------------------------------------------

static const qryptext_kyber1024_secret_key TEST_SECRET_KEY = { .hexstring = "3361b3a5658da0a94cc510ab4834caec892a215a937febbbbf202b3c67187d1bbd38409851e6117a94c9cd65bff5aac0d32233897cb15b16c8808b04"
                                                                            "779bbc0d06424dbc2ab5a7c794c17bd4145b4c707ae2a53757da055800572ba0404d48ba6f2856bd8a1afcbc85fe6b23a8e301f6d98e02476fff9b61"
                                                                            "0dd89754992c609a5a139b7a7ba47e85727bcba3b9700b983782c1dfd3436b410f714a1072d8912d62347c1374f8e385b5580b3757b064f1278a41a5"
                                                                            "d1167599a5b6343597470322c8bc057ca49c7c6b7e2ad8a0467a275821a6ebd299ba845eb718967f3102ba84bd13b5315950370a461ecfd50ae21557"
                                                                            "c7ca8daadc1c449863a35205702b2481cb349860171ed9a8cde1628ac96953ba2314a4cbbca59de0760f8e04bc9ebb744f253ac1062c742654aea64a"
                                                                            "8260407ce999bf59a2f3365790744fd1b432c35811a9783f4d0456f71a2e34098f12e80886573f34791109b24f0f372a284b7f6775bb82619965179f"
                                                                            "6680c226f1be2d5b10d6e2970bc72d6ae92abc6188568429472a84cb30ca0eba66d2c8886ce3be9ef66976156b6cd9c059d0b4103c80e1d91b360ab7"
                                                                            "ef8250b501b0317799684232c74b722769219c892fd35ba81fc12248346a37b53792922294ec7e0449976a48552ce9637ec017a4a1798f60c2e71b77"
                                                                            "bcf17514c79a73e78903c9c919f00975379c16e29a42ac13ba0b9eda14950b196d8aa8c04d1c3020057676f4497291b14ce9409c629eb99943d7e7a1"
                                                                            "f5160c34aa1a3a2c357515a91896229e67b22b913cb1da4abd447f81165d506389383c0cf860c33a637ec47b0f37a80476a3323bb20a997496d3888a"
                                                                            "ee822961609361da99ff39b31be66a6b7a3ec2e0b7140702f5911a2edba6003013bf269c6a78b6c2b57cae8cb055da64df904cffba3f0068361de948"
                                                                            "0753c6d6eb241a1859a972afbec0aceb520279626c37595db1270398d27d9c263daef1c236232e56a30c9e758651ea8733d496b81ab9e74b9dbb119e"
                                                                            "39b96129b519fc675f7b475c7a01ccc557c764905f35db2d502b258fab1208c82b4712c8b09a66e6dc2c9311b903e38e3c0561db465db59b0644fa92"
                                                                            "82d307f4c790a3987ef91a47b872314ecab622c880e913a246c3645810aa8a38553c593ea079af33fb7b2d6aca7e78754c06b5d5424f09aa7e0e704a"
                                                                            "70a228321a968fd4af5aa3b968bc6787c45cac80a4166278e29972ec4b0436323fb42c11e95310c60a9fab55adc0f06531481e40b03017681ae9b177"
                                                                            "5424732c62401977b4bf9cc813e39ccf4120193c8f1841250d69a38ff5510e813ed2458174c0ab0adc3cd740a50e068de7a5b40b357bd8d706ff9b4b"
                                                                            "3ad96afeb36ed3d54a0b40204409aa54d4635668ce450b23310a77cb6c93a2532382031ea19846b22086474ac6eacc6a1a765abdf16712f240f3f276"
                                                                            "443431f58a6c77e39b61712034406906158fa9a197858c37185c85caa7b10db139be9b8686a77c490b8d6fb1c8804746316365a4fa53e4eb5cc3b71a"
                                                                            "ab93c15015435feb42d4a8992489a2ea5153d8022268b71672d5cb7192441e110917e635411469ac72cb42c4ac694c723c3c26798a3665404c7d26c2"
                                                                            "2c856340dc27af5289d88234f1e3cdf5c5619b597286019ad5d48700b66d2ada728e28c2cd8019efa8228f070eeb89292d17afa847c9c08565aec80e"
                                                                            "a5b968a7fa0cdb9856275c82973820237790fe6b29adb0997ae31eb2552390466de8dc6ed31419612638804620fa0a24ad989b52624d7e1868d42977"
                                                                            "35a4917d2c59457624fd268dbce4200fc37fca900ae1297d1a082b879116d3200211c17345a12b3d653f43e33f05010063f41ea3891377d799e4c25c"
                                                                            "2a301648c264cdd201f655c7d7756e3691ccc660b499cc6df5fa031f76b6da56cb20e340fc85875b851abf73878e1c8e7cfa9d3b0a71a18883d70c51"
                                                                            "49e18666504ec0f2a79e5b1895f06912faa55744c790d318ade03feb7cce56854b71c81956d6a6e6094e550c21312c14413096c9cc0f3ef6042c222a"
                                                                            "a6f769341c515030ae5cc0936d7101c21922c639cff2f005534883da6168f4d483e308b19c3aa53c1b472c23aec6c56473bc6582148d4fcc0456d950"
                                                                            "a3471f39461f901b23581799170446f808c611422fa8820324c15d96f1b7a21c755306bb211c0a8e8607ad0730a10c0373c76439870dd8493ab8e914"
                                                                            "11b2559f90a0a14145d3452135f3688abba5e754cbd6746be9ca802ff3c799eb69c55242f2d016380802977c3de2178dacb6b913a76014aaccb6115d"
                                                                            "76a47c704b7675baa47558b7474557e73a4f28aa19a063c934230dd6134b0eb55aa039882f924aa827c2f9b67177382d6a5454e2161cc46540a77579"
                                                                            "f37c1a104a94e8b1134869c433556de761b2d8da3f6b7b2506259ff4bacea98c2ce52bb57cf5b2c58472003c1f2da19c682c356be2b5f2f735863b54"
                                                                            "02693000276d455b97196c5af9107bdc08b8b9c31bb60bbb5f381370dc12f14bbd074a2c338b4b8784621fb83fd59ab7d60338c03759619806ed5c55"
                                                                            "b8b992f33691a5526110d7b9d8148c5ae697ec433eff3b333fa47ae46921eef07e1f9a2d08bb0165527a48694c57460c027b472e0a62214b003a59bd"
                                                                            "568120af931b0f50c3e2eb09b0536007f76e1a87679166498767cf25e640ec0b1522858634dcb9c7243108021c65b231bc941c0d40a812db8d3e2a32"
                                                                            "d7604d31311a55fb16954b0d7f4c8a1b15995f187bbdcb08f5ec08c745908ae589c7328ec6b5b7620398c56578a795b5e5e5c905f714ebf51158bac5"
                                                                            "708b3248803fd1aa647d966a16d00bd7881ee9dbbdfab849551c017865a11d29184a54c186baad165c173803577cf12025e72251f19b9484cfd54812"
                                                                            "c44b68c51128f59a9b4d761426145830e6ace1d4261b682ef431877741149092c2078214728b022fca6341c59c0abbaa1bd1b5a530c7330a92724ba1"
                                                                            "329471b6d39aa0dc8c9888889ca0c660a2b975616fb14cc422ec2c70d805a2897739a73a3392839a7b09cde92097d768b77b7c37a31b50005e316c16"
                                                                            "78e93f8ca62ad18bcce87c0bd2e07da8d939b6aac7e205ba9c45a1ab4326cce598f833b40d06929b791e0cc392b641c39dc771d806b62b890103561e"
                                                                            "97890e3d62c1286727d0dc924dd405c00a86abb23ee892417bf393b58387ca79b3e15aa74661b491278548283a85f56a89b9ab9aabc10cc3ce7c387e"
                                                                            "1c3c985c214c68430418325a21406724ca4dda7657485ab5514a3074b45a1a697261e8c0ca7788975683db41ac4cfa3e5fa68950ebaa331ccc69d10e"
                                                                            "45b3859e61af6b6782c787ccc4381938ab5eee0a55d716800833248ef7556615a4824a37dd126ee3695638270cd312021a812b9cb66b53d76e7288b0"
                                                                            "adda2d8e00291d96136f6c35898555a9855574153e2fd37c9b351553133d5fda0a4ae960ba1a78a7c1445afbbb5eb75eaf186978d239f4223efa0681"
                                                                            "4c71c5cfe3209d20a123c4be53b767360b96a06668e2b0c4b34aabaaa05c0cfb1a82e426e9e548e4897b7dda34a298198d23bb0017a10a744b28e6c9"
                                                                            "749376611116d3ca979ec09d47aa850cbb9862fc4c62e22500960f85880c8a26aa4e3cc382ca0443c6299f4975f8335e21ba67aa14176537cc7960cf"
                                                                            "06988269205c947c53d3590db87385df72981880362cf35437ebb01d242a1ed689b9f24a0415ae1f7b4ae8155e8bd48abca58b3dd719ea5306b9f2b7"
                                                                            "9b92368bd43d9d2b5dfff00d1f2860a46abac0d97b06826a7a4a64d71642b2985798a938b70929a31137cb191dffb74610aa641d30b591d6901a6177"
                                                                            "1a36541819717bac3788d97f7b024c63f57e0f61579669ba0122300114862ff5a930071d3fb8a3f3631beb944be5c55083fc7c33345c74b7070673c4"
                                                                            "05eb5d1215678d205369dc74e2f6627ce5ad44b74cf78356c80b2db3d1a77e7a10c1aa4dffc213f0808e2d0a682bc52ada308a6d497f0dc1bd24f138"
                                                                            "9f0b0aa2671943a8362904bddbf3a76a657385da71d1c36b79e052c69c2cbe23bda85a09fb358f6dd7c55e65260df142154a363fecbfc29b476bbb67"
                                                                            "dc61bc6de065bfc543aba90ce334bbb23ba83ba99308629a27b24646248c347570d6324f9ca069c40b0e9ba8c715ec892613ad95d37ec04b9440ec1b"
                                                                            "9fd766ca617552c95c02ab267595a06d2a55f91bc6fe8040368c38e67cb7d56a3ba75c43e0389e7e248cacd91985044fd11bc975b71c3fc70ab9cb62"
                                                                            "0ac70f5ba80ac60b6264dc33c7ec2896589230a2ca46d82468471c26884e80e02bf6d385585a8bb8c3136aacc400006b2688ba0842437d9b26021598"
                                                                            "1f6b38846298e0018d0dfb75c8a3fe6b3d6e2aa53643b4dd49fd444b88091dc4fa3d71cada128ad7a8cb94bb310c097bfbc479cad9ae0a6add460dcd"
                                                                            "9deae4c6a2307d18b0727a17d536956d641f710a5d446fa4417af665057365a66fbaa8137669b4558185389d9c26c8b5" };

static const qryptext_kyber1024_public_key TEST_PUBLIC_KEY = { .hexstring = "211c0a8e8607ad0730a10c0373c76439870dd8493ab8e91411b2559f90a0a14145d3452135f3688abba5e754cbd6746be9ca802ff3c799eb69c55242"
                                                                            "f2d016380802977c3de2178dacb6b913a76014aaccb6115d76a47c704b7675baa47558b7474557e73a4f28aa19a063c934230dd6134b0eb55aa03988"
                                                                            "2f924aa827c2f9b67177382d6a5454e2161cc46540a77579f37c1a104a94e8b1134869c433556de761b2d8da3f6b7b2506259ff4bacea98c2ce52bb5"
                                                                            "7cf5b2c58472003c1f2da19c682c356be2b5f2f735863b5402693000276d455b97196c5af9107bdc08b8b9c31bb60bbb5f381370dc12f14bbd074a2c"
                                                                            "338b4b8784621fb83fd59ab7d60338c03759619806ed5c55b8b992f33691a5526110d7b9d8148c5ae697ec433eff3b333fa47ae46921eef07e1f9a2d"
                                                                            "08bb0165527a48694c57460c027b472e0a62214b003a59bd568120af931b0f50c3e2eb09b0536007f76e1a87679166498767cf25e640ec0b15228586"
                                                                            "34dcb9c7243108021c65b231bc941c0d40a812db8d3e2a32d7604d31311a55fb16954b0d7f4c8a1b15995f187bbdcb08f5ec08c745908ae589c7328e"
                                                                            "c6b5b7620398c56578a795b5e5e5c905f714ebf51158bac5708b3248803fd1aa647d966a16d00bd7881ee9dbbdfab849551c017865a11d29184a54c1"
                                                                            "86baad165c173803577cf12025e72251f19b9484cfd54812c44b68c51128f59a9b4d761426145830e6ace1d4261b682ef431877741149092c2078214"
                                                                            "728b022fca6341c59c0abbaa1bd1b5a530c7330a92724ba1329471b6d39aa0dc8c9888889ca0c660a2b975616fb14cc422ec2c70d805a2897739a73a"
                                                                            "3392839a7b09cde92097d768b77b7c37a31b50005e316c1678e93f8ca62ad18bcce87c0bd2e07da8d939b6aac7e205ba9c45a1ab4326cce598f833b4"
                                                                            "0d06929b791e0cc392b641c39dc771d806b62b890103561e97890e3d62c1286727d0dc924dd405c00a86abb23ee892417bf393b58387ca79b3e15aa7"
                                                                            "4661b491278548283a85f56a89b9ab9aabc10cc3ce7c387e1c3c985c214c68430418325a21406724ca4dda7657485ab5514a3074b45a1a697261e8c0"
                                                                            "ca7788975683db41ac4cfa3e5fa68950ebaa331ccc69d10e45b3859e61af6b6782c787ccc4381938ab5eee0a55d716800833248ef7556615a4824a37"
                                                                            "dd126ee3695638270cd312021a812b9cb66b53d76e7288b0adda2d8e00291d96136f6c35898555a9855574153e2fd37c9b351553133d5fda0a4ae960"
                                                                            "ba1a78a7c1445afbbb5eb75eaf186978d239f4223efa06814c71c5cfe3209d20a123c4be53b767360b96a06668e2b0c4b34aabaaa05c0cfb1a82e426"
                                                                            "e9e548e4897b7dda34a298198d23bb0017a10a744b28e6c9749376611116d3ca979ec09d47aa850cbb9862fc4c62e22500960f85880c8a26aa4e3cc3"
                                                                            "82ca0443c6299f4975f8335e21ba67aa14176537cc7960cf06988269205c947c53d3590db87385df72981880362cf35437ebb01d242a1ed689b9f24a"
                                                                            "0415ae1f7b4ae8155e8bd48abca58b3dd719ea5306b9f2b79b92368bd43d9d2b5dfff00d1f2860a46abac0d97b06826a7a4a64d71642b2985798a938"
                                                                            "b70929a31137cb191dffb74610aa641d30b591d6901a61771a36541819717bac3788d97f7b024c63f57e0f61579669ba0122300114862ff5a930071d"
                                                                            "3fb8a3f3631beb944be5c55083fc7c33345c74b7070673c405eb5d1215678d205369dc74e2f6627ce5ad44b74cf78356c80b2db3d1a77e7a10c1aa4d"
                                                                            "ffc213f0808e2d0a682bc52ada308a6d497f0dc1bd24f1389f0b0aa2671943a8362904bddbf3a76a657385da71d1c36b79e052c69c2cbe23bda85a09"
                                                                            "fb358f6dd7c55e65260df142154a363fecbfc29b476bbb67dc61bc6de065bfc543aba90ce334bbb23ba83ba99308629a27b24646248c347570d6324f"
                                                                            "9ca069c40b0e9ba8c715ec892613ad95d37ec04b9440ec1b9fd766ca617552c95c02ab267595a06d2a55f91bc6fe8040368c38e67cb7d56a3ba75c43"
                                                                            "e0389e7e248cacd91985044fd11bc975b71c3fc70ab9cb620ac70f5ba80ac60b6264dc33c7ec2896589230a2ca46d82468471c26884e80e02bf6d385"
                                                                            "585a8bb8c3136aacc400006b2688ba0842437d9b260215981f6b38846298e0018d0dfb75c8a3fe6b3d6e2aa53643b4dd49fd444b88091dc4fa3d71ca"
                                                                            "da128ad7a8cb94bb" };

void qryptext_encrypt_null_args_fails(void** state)
{
    size_t olen;
    uint8_t tmp[4096];
    assert_int_equal(QRYPTEXT_ERROR_NULL_ARG, qryptext_encrypt(NULL, 16, tmp, 4096, &olen, false, TEST_PUBLIC_KEY));
    assert_int_equal(QRYPTEXT_ERROR_NULL_ARG, qryptext_encrypt((uint8_t*)"TESTTESTTESTTEST", 16, NULL, 4096, &olen, false, TEST_PUBLIC_KEY));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(null_test_success),
        cmocka_unit_test(qryptext_encrypt_null_args_fails),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
