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
#include <string.h>
#include <stdbool.h>
#include <setjmp.h>

#include "qryptext/util.h"
#include "qryptext/sign.h"
#include "qryptext/types.h"
#include "qryptext/verify.h"
#include "qryptext/keygen.h"
#include "qryptext/encrypt.h"
#include "qryptext/decrypt.h"
#include "qryptext/constants.h"

#include <oqs/oqs.h>

#define TEST_INIT qryptext_disable_fprintf()
#include <acutest.h>

/* A test case that does nothing and succeeds. */
static void null_test_success()
{
    (void)0;
}

// --------------------------------------------------------------------------------------------------------------

static const qryptext_kyber1024_secret_key TEST_SECRET_KEY_KYBER1024 = { .hexstring = "3361b3a5658da0a94cc510ab4834caec892a215a937febbbbf202b3c67187d1bbd38409851e6117a94c9cd65bff5aac0d32233897cb15b16c8808b04"
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

static const qryptext_kyber1024_public_key TEST_PUBLIC_KEY_KYBER1024 = { .hexstring = "211c0a8e8607ad0730a10c0373c76439870dd8493ab8e91411b2559f90a0a14145d3452135f3688abba5e754cbd6746be9ca802ff3c799eb69c55242"
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

static const qryptext_kyber1024_secret_key TEST_SECRET_KEY_KYBER1024_ALT = { .hexstring = "1bd9151e9324604a968b92ac1b6690391c3aa6727516ab672890443830083139c7828962d2c79aa4484d342b82d296655c2477a596ae7dfc491d47a4"
                                                                                          "642ba3dd1a07bed4ac7d46406eb0aae04623662560cdcb9fc2749544db679987a58008a0733ba3082291d1a181839124400a7b1bdcba81ac6bdbc35f"
                                                                                          "97b5b699a7842b1b9fe52b0e22f72f82b1b48b434160815e5823035020b54025819df35da234a23de18bd81330a2172b0601763fc40695229f3aa5a0"
                                                                                          "c448741fda012171ccf98541dde2a893303f5d4aa2de997917b51b37eb217d2c177fc37afd73014a6cac8ed9409ce703de43b5f8e88ed35b2bae1767"
                                                                                          "d684409464554b374fc13557af5761c7286e0f97b1f0d1aa9e00cf1b31b3c955b8065aae8072a0d3558b715b5fcdea552fe73c657a8107766525b519"
                                                                                          "c23526eca8287a519ed7a54e3e6a313b07239f42aa2dbb397df8cd90fb003db1c30287713381764e532b61a8a4e5c8b765962fdd01b0557ac5f2ab31"
                                                                                          "484c7560d10d8579b6b118282885bca8336673875c01ea623f3a618e8044208905472027755615aad29da8e3113532307a5707fc3a7a7f9cbd425c68"
                                                                                          "cc15a6c83b8e3053059e8c498e5016b3b25e5345554f570f29b93fc9923dd3742ee7a4cfd160ade07825906205c1a07025d58964850812465bf7001a"
                                                                                          "6ce75751e4a40d3bc33c945b9dd87cb6d916d970211a167d64c9249d33afb04455715c010ca58d4a098e7b900599b930bd97a3218b67f47635d07556"
                                                                                          "82f937b719cb07f63bf0d37817a4956d2cbe7040a220831a38a55582b49c36ea14a3252a2c4831f1db6a1873305c22bc73ba435cd5919b5c33615bb9"
                                                                                          "69b09d86a68703a84d039110bf37b3982a5baa27541595c7c7cb0d2f0ac2cb7cb81b2807923c48a8c66633ecb219a042bd46202f809a42833fa9d2ae"
                                                                                          "393a96196c25d66a78a31678053b79d422b935035116a45e20b35e3643948d9a3a949139fa724ced2943248ba5ecfc2673f03fa88b1ca654596f4161"
                                                                                          "909064c63348b9ab31fe6993fe22629de6bd0aa01f4932bea8b9b9a84247f7b73b0e60ad3bf03139bbb98ad33d86f541fc3c5425e02ed4f1866763a3"
                                                                                          "fcd244ac888baaf53f9dc6214e9a3bfb8991c533314824b535e794649573a9f34bd8c4ab648563bad0263335b50827bb5335b452d49c681195be986c"
                                                                                          "e106181c9b36686484359c7b5ed85a3ae4394ce8b02b6287e82377e5e0adb536bd391471f04b60083686cc589f6e203bedd8728ad02173e3c9f501c2"
                                                                                          "cd345655f92e57fb663398329088176588865815a1154355cc02a11afca43462b29106266bdbcd86caab97f00bbb092d146754571a02a33673808556"
                                                                                          "cae156fd84ca3b91583ed35705ca74f9814858bac65671c3cce9bdde4471f79b3882474242b05517919eae183b3fc37965d3368fe1b79bc6705f43c9"
                                                                                          "26b6558d340350885494205a541054a2a6185e7b8f0fc9a11ae60fb9c0476cb81e3f1949f1459ea5d97e2ae52e5fd3851104191758bf28e08db54b83"
                                                                                          "3ee18ae432219f957d286a7e5d025bf2d06a32c16261688392ea24e88b8e512356b3865f4e7044ec812c7ae0714ecac423d4a3a90b7e449571e225bd"
                                                                                          "a1b5434ca60751266681fa847f2b25ffc2a68b5cc5e138108a44b9008136a6a4407b87c38a0623b6f638f03aa3659b36fb2a1213746cbad465803351"
                                                                                          "12a2ae29b6476c5b1006c69a2e827e6e6bbfd07246ea25b1326c0b6cc6bb09c2bac3c19f5130a7886a95f3437175422bfd7bab54b87fa3116f97ca12"
                                                                                          "e06cbc205998ea76a8202724ca08c6a92360cc39cb7fa66ecd7a845e8c0d00c289fa052f23f46aa3203854c5abc7acad9504cb2e2c3ed31562537067"
                                                                                          "6d721fbb276ba50896a0b21dbdf73cb4828c1bc157e6c55af76a5c318b5d95c002be569ea8b686c89ac9d3b00c14517443491d1360078e27b47ff522"
                                                                                          "d6f6358d21c1c1953e6d78505d7983a7f87fab4ac7d909a4036216e42187914c47bf501e9b3898a429af6519b1551010acd47d8ab8039d75c6ee9639"
                                                                                          "4f8665f8fa78091344f8789a4904b6f8724f18fbcf449657c0926ed6300ca5f052c37b61ef5871d7a15d60bc4d8ad7574dc66732b69430e610bcf252"
                                                                                          "8beb8595713725e6c0e1e0c808c0448216833d4c924ef5728fa19449c19a4f7685dd014067584c2c74c5742237e955701c30a6914a2ba78b9f670b4a"
                                                                                          "06a2505c288c6c339b26d2aca8b113c9939d15388c9f832c4a4325677a117cb67830e8c76e9030af0739e2c8303a352469c4978bf595c61a4cdde075"
                                                                                          "45786ffb5a8668352546608a976a0d0047540ea3085b0567d998bebb59b512f61e784a798188b5901453b39ab32303582b343ae3ec8ea55a369f8a5e"
                                                                                          "616bae1246c076194e66aa1020a9018a303658d29a8d53cfbe84925ea73f24d14ad3a4218754c17d920fa1aa8f7bb7731a355d2dc9b9e8f627effc72"
                                                                                          "89859d49045a759c52f1a71cb4e6c3ea06994adba2542140f6a1041d73a40b16a389c106224466d196ccecf46659f7b75bcb4e8c82325577a096650a"
                                                                                          "fae7b01b0021990b93658bcf94a27481d72aebe6599dc756fe46c513bcc305fc91d4787d0f3a8621f9c369bcbdfbe8bb1fe78ee6c518ee3515d49855"
                                                                                          "8c48addf601073999625b470622319e3d73d18885914b7031ae2245fc77bc7d07fef00b640a838594c13575554ed980090f2c0c65c42771033a1e077"
                                                                                          "3e15c29e104e33934761476042ca495df1946d18ab6f4a2ca596ce3151c0646095e951c8c7b0ad476941d602854cb34b15c169f073b74f5121ebf09f"
                                                                                          "b0da4f1ea455f5b81a93e1ab67b3079f390807830c31ab564933c9a2024092fcc12be7a4340c7e25c1312208729fd7cdc4e15fd44b6537654b14a523"
                                                                                          "9a058f5c5a33c473307831899d8823e62a28b260addacb99161aa24e9a86e6d8752e9484f5770ac21822e7d01e76f48883ab290b644cabb9b5082ba7"
                                                                                          "7fdc25031a4dfe759558890a27e763f6e74988509d3a66bbb4aa9f5721b7c7f3be889772e9b586c3716d870aa811d6507503541609274c9b9d0de449"
                                                                                          "231cc010f048092c5f9a3008673228129b7bdf5b18c644123ef7aa835b69e021834bd391a90bbf93ec4c25475b23015bbac83902751a548c25aed675"
                                                                                          "a581bdf3c3484ad684df09c4a1cb80a5ec65aaaa31a55a9ef588a9e78002a3a45959283fc1b63a34333fca92ada1781221997bfc6b14bce09bbbab7b"
                                                                                          "a5504a78b6a5b4b77e4cd55d78ca7eafb71a8202002fd2cffe138cc7308c1bd3b42698a78f5554ba12084df7046763a12aa43ebff00610b33e15a7cd"
                                                                                          "5a3a3b722001bf2c05b5aa93860787a9873bf66c3d0b45939fd9c03d694fe12bc2903548f9ca4c62b582d76547f5a58a3304938df89f965509313c0d"
                                                                                          "96363ca8f4cc4e8831f4d7c6c38ba16884019b708bb7892ec995835636056ff53964a072ab9567e1130241e80be9271e1697428bc83e98325dd6b85c"
                                                                                          "18b5af8fcb631707207e6b34f2a74af30a1453809522046b7284aa260623d3693f089001b227315b49510776bba5f85b722c75a2d50cf061704c7753"
                                                                                          "32f79aa0d256409c77d01a4788c43b58b20adb6c2c4b52a88ee41104997dd2401fd9f2364632b39ffc3bb6ac4296e276c0668ac8d788568a2a13026a"
                                                                                          "b7b4487ea119e5802483d3082d01cc98d001c141c1b704c41b20684f10ceff960941a650aa4c819895b15be22def611df8dc878641c2a9938bc13b42"
                                                                                          "af94cba3976b1ea360bfb3caa9d23f2ea0660f968037a890e5f4ae00e880b3606d92056a65848e7a841a86f2a0e5224661c98d84b74d2ea38abf2aac"
                                                                                          "14e7ae71983f2af5429dfbae88932c0bb77b2d4890a83c7eb37371c3c5919ec1cc061314ca253db9472b617549c5287768908f94f09da00ba2e58803"
                                                                                          "edd523c109c8073a8a44470b3ae9b6c87905afa3c4b709255e85900bf5c29a5728e65210d4434ce3295c90c3add2eb7f6e72b88b309dd1b26869e7ab"
                                                                                          "e38c00dba1c90b33572b68a3a35930eab8c9bfd65410804f183ca21db924d60a5f2f744c71b483a7937d1aeb8b8994264cb5cb4ee99146053693c75d"
                                                                                          "d3827dc4b4c5acb57231d92db108cf81d9c90c825bcd5c7e58c90a5f06aee3e1601f21c403c17dc3771a2d6277397151b07b415614658ea03c593574"
                                                                                          "97799c67008048484a1f53cfa0c42bc6033175097f9e427c070703e533ccd6e5088b679682542cf5e03bfdb9ceb213871c5a47d01b5bef6209a6148a"
                                                                                          "44161ec867b5576227619c3b048b576b408f965064b072b440860b8a27aed16712d3b86e2a92cb7de426abf20605a1bd4c656a20e858e5e532c71011"
                                                                                          "1128786648cd0e612a2cc7514417f97540d2b83862288b396b63fabd55e8cba7a0a7cf382346d9d37c31da4f686315b754f0af0311a8ee0496006655"
                                                                                          "db644da053970f5cb342607efcf5be389f3640095f8c553216f189ffe2f2578f019beccae3fa38048fc827dc1f1276d3" };

static const qryptext_kyber1024_public_key TEST_PUBLIC_KEY_KYBER1024_ALT = { .hexstring = "67584c2c74c5742237e955701c30a6914a2ba78b9f670b4a06a2505c288c6c339b26d2aca8b113c9939d15388c9f832c4a4325677a117cb67830e8c7"
                                                                                          "6e9030af0739e2c8303a352469c4978bf595c61a4cdde07545786ffb5a8668352546608a976a0d0047540ea3085b0567d998bebb59b512f61e784a79"
                                                                                          "8188b5901453b39ab32303582b343ae3ec8ea55a369f8a5e616bae1246c076194e66aa1020a9018a303658d29a8d53cfbe84925ea73f24d14ad3a421"
                                                                                          "8754c17d920fa1aa8f7bb7731a355d2dc9b9e8f627effc7289859d49045a759c52f1a71cb4e6c3ea06994adba2542140f6a1041d73a40b16a389c106"
                                                                                          "224466d196ccecf46659f7b75bcb4e8c82325577a096650afae7b01b0021990b93658bcf94a27481d72aebe6599dc756fe46c513bcc305fc91d4787d"
                                                                                          "0f3a8621f9c369bcbdfbe8bb1fe78ee6c518ee3515d498558c48addf601073999625b470622319e3d73d18885914b7031ae2245fc77bc7d07fef00b6"
                                                                                          "40a838594c13575554ed980090f2c0c65c42771033a1e0773e15c29e104e33934761476042ca495df1946d18ab6f4a2ca596ce3151c0646095e951c8"
                                                                                          "c7b0ad476941d602854cb34b15c169f073b74f5121ebf09fb0da4f1ea455f5b81a93e1ab67b3079f390807830c31ab564933c9a2024092fcc12be7a4"
                                                                                          "340c7e25c1312208729fd7cdc4e15fd44b6537654b14a5239a058f5c5a33c473307831899d8823e62a28b260addacb99161aa24e9a86e6d8752e9484"
                                                                                          "f5770ac21822e7d01e76f48883ab290b644cabb9b5082ba77fdc25031a4dfe759558890a27e763f6e74988509d3a66bbb4aa9f5721b7c7f3be889772"
                                                                                          "e9b586c3716d870aa811d6507503541609274c9b9d0de449231cc010f048092c5f9a3008673228129b7bdf5b18c644123ef7aa835b69e021834bd391"
                                                                                          "a90bbf93ec4c25475b23015bbac83902751a548c25aed675a581bdf3c3484ad684df09c4a1cb80a5ec65aaaa31a55a9ef588a9e78002a3a45959283f"
                                                                                          "c1b63a34333fca92ada1781221997bfc6b14bce09bbbab7ba5504a78b6a5b4b77e4cd55d78ca7eafb71a8202002fd2cffe138cc7308c1bd3b42698a7"
                                                                                          "8f5554ba12084df7046763a12aa43ebff00610b33e15a7cd5a3a3b722001bf2c05b5aa93860787a9873bf66c3d0b45939fd9c03d694fe12bc2903548"
                                                                                          "f9ca4c62b582d76547f5a58a3304938df89f965509313c0d96363ca8f4cc4e8831f4d7c6c38ba16884019b708bb7892ec995835636056ff53964a072"
                                                                                          "ab9567e1130241e80be9271e1697428bc83e98325dd6b85c18b5af8fcb631707207e6b34f2a74af30a1453809522046b7284aa260623d3693f089001"
                                                                                          "b227315b49510776bba5f85b722c75a2d50cf061704c775332f79aa0d256409c77d01a4788c43b58b20adb6c2c4b52a88ee41104997dd2401fd9f236"
                                                                                          "4632b39ffc3bb6ac4296e276c0668ac8d788568a2a13026ab7b4487ea119e5802483d3082d01cc98d001c141c1b704c41b20684f10ceff960941a650"
                                                                                          "aa4c819895b15be22def611df8dc878641c2a9938bc13b42af94cba3976b1ea360bfb3caa9d23f2ea0660f968037a890e5f4ae00e880b3606d92056a"
                                                                                          "65848e7a841a86f2a0e5224661c98d84b74d2ea38abf2aac14e7ae71983f2af5429dfbae88932c0bb77b2d4890a83c7eb37371c3c5919ec1cc061314"
                                                                                          "ca253db9472b617549c5287768908f94f09da00ba2e58803edd523c109c8073a8a44470b3ae9b6c87905afa3c4b709255e85900bf5c29a5728e65210"
                                                                                          "d4434ce3295c90c3add2eb7f6e72b88b309dd1b26869e7abe38c00dba1c90b33572b68a3a35930eab8c9bfd65410804f183ca21db924d60a5f2f744c"
                                                                                          "71b483a7937d1aeb8b8994264cb5cb4ee99146053693c75dd3827dc4b4c5acb57231d92db108cf81d9c90c825bcd5c7e58c90a5f06aee3e1601f21c4"
                                                                                          "03c17dc3771a2d6277397151b07b415614658ea03c59357497799c67008048484a1f53cfa0c42bc6033175097f9e427c070703e533ccd6e5088b6796"
                                                                                          "82542cf5e03bfdb9ceb213871c5a47d01b5bef6209a6148a44161ec867b5576227619c3b048b576b408f965064b072b440860b8a27aed16712d3b86e"
                                                                                          "2a92cb7de426abf20605a1bd4c656a20e858e5e532c710111128786648cd0e612a2cc7514417f97540d2b83862288b396b63fabd55e8cba7a0a7cf38"
                                                                                          "2346d9d37c31da4f" };

static const qryptext_falcon1024_secret_key TEST_SECRET_KEY_FALCON1024 = { .hexstring = "5a093de0ffbff901df6c81e87c3283fc30862ff8400807f093610f044f17a107c24f7ffc207e2d8800ef3bff6fc1008dfff4c4e83e01ef830fba20fb"
                                                                                        "80ef804d83dcf73a00fc041fbc6e7be32f802e0442b0fa300bc037c21f802120bfc0ff640f042e6c02188451fc1de7c200036218fc4008210f7c1083"
                                                                                        "e5203fe00fdee07e620480efbdf178030177e20bfe0f461e07c3effa0e87e1ffc4300c00e17c3f907f17884f7c9e067c20fbbef7fde084a3f841e00f"
                                                                                        "8307382f0403f0760f803e00480ef8a12885f06b9ef8c1fe940407bda108410ebe2f0b9e280020044308b80004220fc600fbe3f089ffffe0f93b9117"
                                                                                        "bd187fe17bdc080021787d003dfe1bfa008a301783f6c420fc60e8cbef07dc00f22f705ef8c8127be207800f8be0187bbf78021779cf082128022f80"
                                                                                        "3f10fc21ffbef6c00f7be1f007ef78000fc60f13dd10c7aefc1b2047fffc5ef843d010211685ee07bd01079f87dd09be20f3a0f0c650042700080f7b"
                                                                                        "9d087bf30ba4078210005ee8ffb0fbc1f045e3747ff93c1013f9007c31f863f7802307c3d87c1ff401f803ef903b1148307c25087bfff7a1f881dfff"
                                                                                        "dd0f89b2701f1fc3c2707f0803f298c110c5edfc1efe821f8ca528360f80001eb64f8482083c0fe8420f8200ff9c10801df7dee006517fa0f8fc1e8c"
                                                                                        "63f07bd0743df086200ba5083e4ffc1d007a0ff47f184450f461d0be3e80631904111020ffc40e043d2783fe8480f7ffe077ff1888230022e7441100"
                                                                                        "601741d3746319061d8bbe0845cf009f077c4f7f5f09000f003cf881dd847cff001f78bcd87deffc46003c0f84fd0037d1f4420ffe118864f840200c"
                                                                                        "1d280630fc600789df0bd90082027fc1173c207cbf20f9f0f8a5eec23204800fc41e037d0fc2008861e8fa1efbe50085f1077e0804210fff17422200"
                                                                                        "40f9403f186117fbdf705ff6c5e0f841e0064e8424f07e1f08df1ffe1c83e320c820141f083feeefe40fcdde0841f881e1f842f03a1003a20fba0290"
                                                                                        "6200c1cffc43f7fe2f087c18020177dff7be1ffbe04003d277c0e8bfe0ec4217bc000401083e028820efcc03ffde17823e8c0408f7f3fc01ef842108"
                                                                                        "1ff0342d881f100a5f8443f83e0efc1ef7441ff41df783d1f760f03bff789ddff200089b0045edf4410f041e07a21741ff746400422f6c24e7fc2f13"
                                                                                        "e0e7c21ff87fdf7a21e47e20be2088602809c2801effc81f900417bc01fbe1e843e10ca1187a120c2107ffd410beef802f8cdef73ff313df1745a07f"
                                                                                        "dcf787a10c82f14211f85f17fe0287bf1881dd7fff19c3e18bc0007e01743ee0000f783f0001f083ff008a0f73bff03c0107a10883f1fc21f8ce1e73"
                                                                                        "85203fb0f363f8fc3e206008f81ffb7a0f35f0870029001fef45f845d09042f181dd883ff83c11845f207c300c200907e1047e0738017b7e18bbfff8"
                                                                                        "2106fc0efc5f0ffc0004421f85c1803cf6fe21001d18c01e0b9f0085e1fb8528780c9038f0c3f07c63e7b9e00c022005cff0c307be11878207c8309b"
                                                                                        "fe274442783ee90a210fc4e94631900420bc4f7bdfe7ca1193a00745df1c42e7fdd0781a17c40167dcff7c0f80000fb831fc5ef7c6227f83f87a4f80"
                                                                                        "3e07c4517cc1f7c0117fc2204c60fbdef8cbf08bc0ff0021084010000e7fbfe878039485000610979d08c9de6f83fffbd0901c0e83df7bdff0040200"
                                                                                        "02b8803003c4f8ca0e87a01704008bdddf821103bb08c3ee84240872117f8330c20f805dffba3febe010c061039d17c20ff3a2cf03befc0217bc2073"
                                                                                        "bd2802108404f8b9ef003ef77a21087d0146100460d5f615f6fbe307f8e61efd0c06e83a0406facf02e2f7fcebf70c043a13281ceffa14efeb201ffd"
                                                                                        "07f81f171704ec2bdaf32ef702fded28e20218e1f7fdf6091bfef7fd070aeff1c81f1ffc27f9d8f0f2f9e20edfdb1f19d5ebe3ca00fddd2a1a061313"
                                                                                        "0affcb1ad506210a020a1913df12130c2ff1371208f3f6e207f3c304db0105fbf936d8140b2403eb3608cd2914f6132609f0e6071504b1d3f5ee35f0"
                                                                                        "c43cd0e318fb270d1b1af31d3de7d6eae7083a1b1410dbe4053108f9031cec07e2f8191ff9cc363c110802f21af9e8ecfa34fedcfee3010513010523"
                                                                                        "d7cbfc2afa1811f9d0ef131dfa1ceadd09facced050ffa0bebf01920e3cdf124c0e1efe5fa2bfc090b1ff705fd001006e6180803cdd74023f7fef21e"
                                                                                        "e1fb02f7182e0a013d0bf7ffe1da2bcced18f5eee3051add060df5f513eac71a03180a2e1b28150fdc0113fbd9f4ef320009e90d0dfd07f3071fe419"
                                                                                        "07f8180b1222120701070cfde504f4041be401f12211e2e6ff0c0806f715e1040ddbf5f20ef9010b1cfdd5e4f023dc17e818f60d0c02f9d2d70ee908"
                                                                                        "d30a15024df1ec06f0c6010200002119e5240a14ff23e00116eedbebe32906db1dffeaf2f6df14e61adcede5061f14271f3408ef20f6fb02ff1bf6d0"
                                                                                        "ce06f9eedee5dfebfe3dfdf113ebc719e81516f6fc07e50f1f0d240b04ee12040c06ff01fce6f9eb04f80ffbf6fc1adffc21161208e1e80bea0b1601"
                                                                                        "0008e4efd1d2eae1fcf2ead80afaea090f11d2200f23040715ee03ddf6ecf511ec0fe4e9c81628ee2204c9f9e711f4f426f0061b07170c1a3aef31fc"
                                                                                        "020fe121041a05ed1e0ff81508ea19f9e104120731def202e41dbcfc0fd0ecf71dfbf123f01316f7f618e50df3eb3d01fa3403162ffef6ce0c0b1a0b"
                                                                                        "f6e50ee21cfcfc09152b1211d233de0cf80017181228e21410070fe1fa05f9fb2218f9d1f61eef210000f8fce4062cfcdf0404f911f2cffafae7f7da"
                                                                                        "fe0ee601fef303002e03f429e90d08f824e01105fe4720fb0808f4edfd041befea0b0af409fa1f3fedfaf9d50c10dbf82b26ef07421ffc100bd6f110"
                                                                                        "cc2726e012e4ec12eed9e4fb0debfa200bfd3520db01fed204001e16061b1213fb040c0701f92eefece6f5ef3af9fb11e80afa1906f21015eff4060a"
                                                                                        "3007f81b0bfd1d17031fe9ffd4200debf413cefb1509040414150e1dcc22da19191308f6ed09f9081cdf0e1ee8f22f06ff1614da0fc21cf0f315f8dd"
                                                                                        "24483cfa0f070ff3f3db010716d2f317f5330ddb44dcf410f0f6f9ecfde80e11e80b1419ee1613f1f5da07fb02231ac01115f9ec19f7f6ecf60bf003"
                                                                                        "05ea1507cf1a0cebf2e701072504190b0ceb201af7001bc3d307fdebe0f110de14f8150b150e1007fdf6f000f61fedf304fb330ef5f4dd01fc13f8f0"
                                                                                        "eae701201cee0415f2e61c02022701caf61508e3f5f62d30f6" };

static const qryptext_falcon1024_public_key TEST_PUBLIC_KEY_FALCON1024 = { .hexstring = "0aac4a3fe8e8db55b894e04385237a0dad26d5925b4c8da1a4bb88ce2154547db4ba8c76ac18d91507477c0bd9840ac751360c29208bc228641475bb"
                                                                                        "8091a4ed9d6c49c3095e6f2de862a09f2786b72dc9321f923b074e8f03a10ad43cb24ff2b1666153e29ab35be2791da96efa0fd0399de80a851d4f4b"
                                                                                        "50750bc38623cc7d0991f9b6913a395eb36799499a14d625f3df6e8c8a1a336b5fac493030b9570a0566662027c172c570bab98f1587d3c682b80195"
                                                                                        "9d4bf48e5e7c9b95909d4bb451bbb69b7937c834e38b452fab32ecdbd1176d67d4546345100b50f2b9217316b9397a81a108566f3902f58634a37f41"
                                                                                        "99569ac6a099b12d2ac4f85cfca9beee26f229755d19fc796908676ea2c4a2211d0897723c6031e22278c9cb66384ddd47190301a11995b7199bb608"
                                                                                        "ef0c58368d688a9d073d98b932e805fe4d1e934538074171113716fecf870ce6cab2ea8adf7cc021e212e4ac6c6d088067279abdd5b24bd5459a0fc9"
                                                                                        "5f92316fc15cac726446195c32fd8e5a1aaf6f723c261a7fcd8774e0ad86a76d6d48bc3498c191caa3e901f5db278bbb601f668346e246edd5a163d2"
                                                                                        "0986e5f129e1ad3f3e65bd590b426d8cb5f0f4192f563c5c9e978700435a995c914fc2923af48e6153557180a984216005d98bd97a7b8f5c43254085"
                                                                                        "571685571790c75ae9dbe54ca19cd00babf0115e53623197c7458aea89c0670808b5b3d3691025a2801d17181cd5392d7947250ce0235541d93faf94"
                                                                                        "2c6830dabd518c0d0438130b00143508bc9bfcdc6855292799bced9a283a7f51ffeb15981d35b9f84f22531c24c4bc9d2d7c2266506494da9cc2fa1a"
                                                                                        "8be57da210cfcb11a943bb694317ee5f592dcc6cb24ba41a759c4c05eadedd2ee2b39095588c71da6b300c07254cd0aae2c415204a3a0ec1de921615"
                                                                                        "ea0ccb122a70af02112534517e07100b38e96ec22109a6a433a0beb6e876304293b43ddef17419de6e0f1af3a80d09d04cc1467704026b72c6dcd897"
                                                                                        "20781fa85620d89cf318d81e8ad08d991f0e210af89ec54d6edcb0cb9dec20ec9652c6a4c301a66a36a68168011ccd46199ff987b4954a64eae103f8"
                                                                                        "5e37081dbc41884c973552a43a6af0828f61ba0d2e9f28ce99e252bea8b177293c1ef0f5e6a70a1bb7316d2097c4205d056575d0565d66800763b0e2"
                                                                                        "a32e69aea24bcdf885ce20337f4274140ecec402ab0e6e4d5a9463a9894048b9a9c81ac5b4b8d7b54a54f200d699959dc1de11814a40562eec77b479"
                                                                                        "450f90d080506eda1268701cfd5c55f71405114cabd1b39a01b009e2f0cd53df48fdaa12b2242e8f747c2a5b01a9528dc26414aa99997c20aad50743"
                                                                                        "9b4a0a41415d42a84024303d6ccd51386013e3d94a0c05f957bad880a928fc9791caba380d6bb206a214abec574847c03d130acc523016727350d364"
                                                                                        "cdecbc8a5628f5cdc78481d5ec00dbe4c0b214005350879c49da3d3406527939b6eb02a3defb111a3988e12d1e7546c838422e8548a86973f007cfa6"
                                                                                        "aa620a1c636628c951f5691ca49428119703da7aa58e5eab24e1844e3d4aa4bc8fe1201402a9f284f1b9aa981808dd833ac1ae82272f202eed64215e"
                                                                                        "abeb162eac356b85967d3223a4339d71af4cdca388d4bf757681c94b589aaec42e61d9519c550c37b5d10d502b5cafb4a75ee20b61b7f18396169af1"
                                                                                        "2df611125a073167c7906cd7bcca4bd0790350bf2dbb93398fc13ba8f9090005fe1c0c50e43caa073115b7c1bb50d88de55e020498655ad9a753eecc"
                                                                                        "607518e87368cacc5b1cfb400867d77539a167daee9c39cd5576abdb4c35b6de148483a418405e077f6db060dd3b63b09bf667f50a3359aa4faa1cd1"
                                                                                        "41b7953084a857b0cb4a0cbb482da41d411908d63788561e6f118c22986309e1ad54e564ef0b673866e4a6e5482b02610df1a309cb71327153491895"
                                                                                        "92f56217fd692702ee3a831399769940efd77056be991c4c4a7812653de631bb2be3dfa05a1dc4a45b378f6cb7494eea5dab65bf908ec6999d860719"
                                                                                        "6384350852d05be60a7f02c12377699b7c9f4c1b46a3006e9df5706260dd687d75cb39a04cf8579e5df2bd45a5641110c2facf6e36aec8441ad38c40"
                                                                                        "fa505ac788f27facad570551aab6669c3532c7092cc8ed28518b0170b0c9d54f139eb7cefd210362db841a3d89f7eb6f5160d429a456af3999d14879"
                                                                                        "eaa0b282fe68cd599815b1ed62c65630be026af5e24364506d7363cd070c4bddbb764846a611c23998799847276dd8d19a22d19e45f511be2fb4697d"
                                                                                        "16e8be66d69b4dadc72b16a997161b9aa9de296cac518a900f0c0048008629d950b749611a3029636fa09b06d6ecef6831b519920bd429c97a38b256"
                                                                                        "0a5538f535a2541d0e4209f383816d67d124a7b5624b77eefeebc2232d51ee0f2326e2dcb9565a37a7934a4eb5d73b05521809ba02477a098e77e143"
                                                                                        "b492e78703b66e6763a628a00c01c5f028f96f01ada5ff01b038165ff7d40444891d35a87e4ff100e6c328f050e097d149ca009d68" };

static const qryptext_falcon1024_secret_key TEST_SECRET_KEY_FALCON1024_ALT = { .hexstring = "5af77a1007fde77ff0887ef0040d8804010bfe885ff8024ff82317ba1270241f42207b40fffbe1743e01405187dfe03e01ffc1f035bf17e01041830b"
                                                                                            "e11683f193dc2847d0f88137fc8f8bc00741e0fb7e2f3ff1081f180b8dffda004270845df8400df7e2203bfe8c5ecffa11805ef88201882816fde077"
                                                                                            "be20c01f0ffe007de273def74a228080f83c2087830884517c9b28bc1104210f380f040227c601045af8b4308b03e0fbee743cef780f87a038844e14"
                                                                                            "60f881ef07be1101d2fc5e0fb86f001f27c612fbfff9000f079f10441184231043fd805a0643df93bc108201040018c022043af005fe7fe327bbd07c"
                                                                                            "1c1fc87e7fff17be2173841851fff0420f7fd0081ef97be27863e78c207c9e3f8a0f93a2093a3fff9de745df9022f73c2e93c2f7c5efffe5ef01fe8b"
                                                                                            "c407be0f8023ff445007e00039c17be00e3ffe843fe7f9ae0c1d18c3e1801dd6fa518042f87e3068e0f70bbf846008840c8058e6802ffbc207424d84"
                                                                                            "0000c830107fefc231935a0000120842f907fe003de7f8418c3fef8e2f7c3bff882107c3e9463ff43d1fc03f6c0007821083e3df7e2e8c20df86007f"
                                                                                            "bef1862f0fc1f843fff760e7bc20f89ee8c04283bc2ffa4f03c01143d0701cf8840104211849c0fc1d007a00f7c42fc0130b62eeffdf039b0783b06b"
                                                                                            "a410c211903fff45ac8fe1104641fc41ef0400ffbe18c26f0be32833f1f3e11703b0fc86f87e0073bef846007080077a5e6c7d0848210fdc20cdee90"
                                                                                            "2408024e0c452fbe507fa11f93fe18602fffd0f7ffff50119084ef882ff403203c6ff45aef7de07f991185ff7fa028b9ff8c5c0087ae7f61278441f8"
                                                                                            "42effa00781b17c7ef78a1ffc81f87bd1084100400ff4222083e08422f045bfeffdd83bf2840300741f87a200724e849ef901aff7e2004be0775fe07"
                                                                                            "fcf03e0078bd087dff88432803b27c0201764084dd0001d377c4e043f2fc230948300be2e08440fc02d97a610c2717f9ff87e01783bf88030ff80108"
                                                                                            "410845c08cfeff39bffc3e2f444f882417f62fffc1e07a1efd0010004e8842078bae8341f1f7e07fa31847ff042017bc000ca31881f0f802f9460d83"
                                                                                            "c3ff43d2847f1841ff841d1093f0033e013bc0fc61f0ffed6c8607be2084010fb20c882117fde188e40fc7ae6c3bf945ef04011006028b61ff85b07c"
                                                                                            "0017c5ef0404013a1103fe013de17b61e8063e77e0d005d0f3de0939eff05f177e00f84120c3d21042073fdf08002003ee80a1f6c80083a20045c188"
                                                                                            "4117840e08601f7e4d9003e07a0e7ca00f3bd207bbe0c23ffbc3204230eb7b0f39f20c1ff83ff08ba6e0020007c0e9060074bc07fffffb80f7bbf0f7"
                                                                                            "c0f041d0f41fe787f0046109061f843b27c25f781b07c41f8780d97e207ffef0c9d0134218fdd0f81eefcdcc8420188a0f883cf8c420804107401d94"
                                                                                            "00098031ffbee6fe1207c10fba20881c203e010068dfffe3f7fe083fe3101bd8ba417c01f8ffc0ffa4e00023789f0f7a2ff49d173a5fffa326fa1018"
                                                                                            "9cf04e1207e0fe8040ef9e18360e837ff7400dffff0ffff18861df7a5f745e1039df779f18040f740510024e87ded9061fff9f1001cf882208421008"
                                                                                            "1d06c26f7fdfe7b7df743f1a3de17c6300c43e0728ffc83e0fbc00020184631f7e2e183aef7fce90212104000086f88610837f00bfe1785e06ffff13"
                                                                                            "80107e5193e1d07dd00bfde6fa0083e218820f84e111002ffc1cef82407c60ff821f7fe30049f07be02907fe8bdd1881ee8bdce78a209042f0c9f27b"
                                                                                            "fce8ba208c632743c0fbe3ef0bc2681e18483f942409340ff8ed192ee8e4100aeaf4081c07ec0f0315f1040cf3f0fb3210dddbd20b18f9f10913d001"
                                                                                            "2315f0d9f1d7fcf5f2241625ec0de6eb130deeedf10b21eb05fe07ec081adbf4e41632fb06f3f5dbf844fc0fc2d609fa13f406eb06f712f3dbff1d2b"
                                                                                            "fc2002f706e9f0dcf0d4f2f0040ae2f3fe27d2f0ffff27dda2ecebf7241bfdfcebec29211c2313081ceef022f2e2df0800f0f01323cd1e1401e21526"
                                                                                            "1428ecf4e6ea1afc0001fcdefcfb1205fa200d380bd229142e1df4d3fd04fa1ee0f4dedeeee7ef1239fe02d2f1f2ff12092f2704021109f3f4f1daf3"
                                                                                            "e3f52615290710f3f2133b14e3fde0f0ff1203fd18e7e9eb05e317f7151201ebf820190a44fdfbf7eff708f92103f3ebf01227350917f2e21017001e"
                                                                                            "dfc9d4ffe409e7fe22161a270ef7050bd2e2feccf00ded080cdbede8ee20490fde0df3f32126f5e70132f0d61c0a011ee8060808e8fb05fe010df607"
                                                                                            "e807fdf7ff2d01f40e0bfa1adaebef2c09200b00d2e9ed40f4ebcf2808feda091f110ae2d1f8f0e459112217d1f90af609f90b3d0ef2f8fddee0d00f"
                                                                                            "16d7ebffd101e1eb021814201dffeb352ec71c101906e505091109d5fafdef1bebecf3f811c7e10b1ffc460b0ce02e20f1e1f03010ef1eccd112e112"
                                                                                            "1718f7390c36210d14e73714e0fad90ee0d92502f9fc1223f400edead1faf51908d9fc1c21ffef1204f8bd18fb080008e8d41de3e30938bf000319db"
                                                                                            "e323e1d7f90ee3fbd5f31ae6ea0c37e80b0be8da021e1c17db072df5e6ec0b122edff61c031905c21ef602fbeadaf71aea1306fdfe2100060b1df8de"
                                                                                            "fa4926fffa1d2cf101d52611ea0415f91cfef403d40f20e7e3e3f4cae0f3f3f51100cb09f416f9131015160c0fe800e22bebc31923dd14f1e822fbe3"
                                                                                            "ed23f3e5f70806ebf0c0d43b18d3e61812e803d6001e25100018e01f0cfdd3e519d908ff3de6be15081501ea1809f2f7291af1ea15d7d8d5e2fef1ed"
                                                                                            "ff10f2fbef1d0c1fe9e6d9120ce2c707ef0b20eceb1432ff3ee2f406e8f525efef14f7fd02df06eb0e000123d81ff1ef22e6ef0700122708fa2ffbe5"
                                                                                            "161afe0b1efd06d41809dcf30b1aedf0f023290eeef9f01a2411ec2ae20401eeeeda2cf4f6290801fcf227270ffd2af9eadcf8ebe4f5e208f620d821"
                                                                                            "0519081407f8042112e30f202e2006f5290bfbf130d0fcf50cf9f305ec0ed7fcfefd09e408231d13d1dbfd05ee042104fff311cef9392af2041a0af2"
                                                                                            "1311ea15e2ded63211dde40c1a1ef2e4fdf80c1321e50803032408120a30f6280cf7deef10e0f11d1d15ccebcbfc12d71bf8fee30dd6f2fbebfc2e07"
                                                                                            "eaf90afd0c0e0becfe0ed7ecf8100edfdc3c2c1f00faf6e7f6de0bfcff0bf7ca2f0ef54a07092a03f71d05e8f7fcf629faf60418f114e20e01cf0c2e"
                                                                                            "ddeb0e10042221f6190a0de01eed2e04f32eedf6ebcfe4d207" };

static const qryptext_falcon1024_public_key TEST_PUBLIC_KEY_FALCON1024_ALT = { .hexstring = "0abef63baa97044a6a4031e894624bbeb595789a9adb94b5ac30a4a64a14684d1a8e4ce05c8ed0143f99f9abea9ba93088fa666e363300161c15881f"
                                                                                            "86b8999089e0f04779dc17314c2219b2d13591544b7af8c120453a5dd6aa24c94181942ba71681624ee342f4423a48d06f7ac969f90bc55082322491"
                                                                                            "2c9d1f92ea07bb54ae8ca53e0f6a23323ed3deac714cf10d31a723b2858975400b1cf423a92e21b6d78568548f6575de1505f8a7e70bc8b410edb4da"
                                                                                            "a1263f170607a0c8dc4dacd431c13aa2d650be5b0559585a4d29e5212f05b35efa4737c2a9b50aa2c5d3ae11d814e9c8308556b982c09b702da56238"
                                                                                            "dc01aa9a10ff638c2773cacf66043002b483117e68117c9317621b1e9dab51c605df6998edb732c0849e08ced9c5651048b94a9600908e79b12bcb0f"
                                                                                            "0e2090764ee3148f737c82e008815dcd4d521c2393206a65327eb5a1889b973284a70ee73e04dcb2e99eec2b238043abde6009412a19e4cac6bf5f19"
                                                                                            "b1f723523d0092de0750a8977b8503db6ac7105219f5637a9361922dc22a17a4d671923799136be06be58b162ae2869f454f69faaedd47950bd229a4"
                                                                                            "08a5b81e551a5799359c59946118754928e4a65994c291e20dc7ea0c7b761dad41caced40d56cd3b03aa2418c5e467452bf5294e352b3f1cc121b9d0"
                                                                                            "41a39d4146e6e0316825daa45697c3b29ed79b7a4023f25cae09d4cec1c2c28146ad4d96cae9252d9a18d4660c8e787a91861492813b6acbb4ed5368"
                                                                                            "68012d4738e2d994fe5ac0781f626409b938e1d089a29d45c91bd6764fe643c76b09fa39e2f4b1281a383e64966b3669b3796c2f99b7e79d02799b97"
                                                                                            "1657a91a26aa16eb19c401e467287a2eab18d2c6134e85f724dc2a10ae841b52369d85ce2f0469227235da26ee639c2f60e38c6d0c10adf89bab5413"
                                                                                            "a9b523cf5e5660ae3ef4bf5da78fd80723c88f4f4ae5b353938eb06780c9c4648e3998302ae4f797f1446543d74f0d7f29a9d6194c009a1a210c9780"
                                                                                            "eaa50db80229e9696938b6681b7eecdf67254705dc4e3d999413464f56e46801ba6bee655e53ec45c89757e3ab85682378dcb37a04d5602767a78906"
                                                                                            "2690ee078b84a6693337c2965d1a5127ded1f7532c3ceb085a7834beb8d4395cb37cccaef0906377acd5eb72ceddbe1ca1c0250651dc8589cb9395ab"
                                                                                            "3f90f59f59a5c3096b316ed7f90d4a152a7aa8085cf6a61e4cb8d40bfd39959c771997e426fdf3a53cde48b3d0864506535e5f9caf57a65ca88f4c07"
                                                                                            "9bb94578af346855342f880b856b3bb9279ab56610e2340e973c7ae925e31c970005c50bac47f894e50061c8e44d790a0c52b458051095a6e428881e"
                                                                                            "04054577b96eee328945713415596aead2a7a09a2616eaa8f68624c4642d897918a24e45d8a601cc4e75ac62ea5b5f1ddf4c20dcf790953c674db3f6"
                                                                                            "fe4fe931a68e23228cd930c53450ff8c5b9004c857f26e3806cd6acb2a2ee49dacaeba8ca2716a89828734a9596d58eba1ca8a108e8a47d5e05b6fab"
                                                                                            "01eaa4499011916624d30cab757438a051d6aef9870c7e647dd685139884d14213a715753c99cc4775538083d814970a138d05a339e7d89fe9f7734c"
                                                                                            "e08622e464b0eda60624d2fde8ba139d75154571dc6c979edc07e8fa6f81bf44ecc45316684945c347c26edc6039d690f62a291c1ab8e6a653358d0e"
                                                                                            "8a2b5daadc68d5d353e81c8bb5494db3108112a276d3808a24fa9d8870d2764a9c472038827e2cae9ae196f4482e12802a12e8fc28e7119a92d40f81"
                                                                                            "da29f0ae1a22a7167056cb14311b9a740654a3b74b0904099bebdf6be5419573f64c87853d753fe9475d6a202d7d22ade9efa876c0f3cac52ba86dd1"
                                                                                            "aabb00981540fca2f34efa929835b573d65f2f34d16ad7a9302f824ad28493197652e7e5a3e88caf548d020ad78263d0bfb7910bfda70c6e9b315eb2"
                                                                                            "78a551d03695c7a292cda787d409382e7a3858d72031418729a96f6b8b9041db6608f00e1ea0315761b42b6e55b497e87002aaca4982505a7ea2eaa8"
                                                                                            "c820827951898ac850b76bdcede036a38c7fd1a883e200368194fe84c1ee9081fc2273ce2f20a93dfbf211d429b0d089d70b2ac9a0711ab28847b329"
                                                                                            "251d943824bf0d16fb0869db7366190e9bb7c90e3c280426851d1f3e1249c3cd5c93a0118446f90308b19689c4d1e0947d18f2f378a5bf9514366580"
                                                                                            "518c0359a497ac66631d50ace2aaaa558dfea417a2257065c5c12a3548fa2d0ef528e1c9ec418c4649a911b549fabe8212c0c13b4278eac718f8b67e"
                                                                                            "ed95a2dcec3554ebe9825895bf91fae4af8b8e764df2c0465b32206a1ef75041695f0996041319bc62a493e1b4c7198cb0f16b22c6749711ccbbe6c1"
                                                                                            "e40f1eee234918cc2e4065c6951c965ba8e25a6128cf8bcaaf07ba50442385cc63bfee300920317bb195948834ad30180c5b525cf6129b16376b388e"
                                                                                            "9525e4cf9cee139b829fe8a2aab5e4f09657bdac5ef1789b3c8209a817984d4b665478b1190f4f9760ce56b2e30e7f1c360a0fc687" };

static const char TEST_STRING[] = "Zwei Dinge sind unendlich, das Universum und die menschliche Dummheit, aber beim Universum bin ich mir noch nicht ganz sicher.   - Albert Einstein";

#define TEST_STRING_LENGTH sizeof(TEST_STRING)

static void qryptext_fprintf_enables_and_disables_correctly()
{
    qryptext_disable_fprintf();
    TEST_CHECK(!qryptext_is_fprintf_enabled());
    TEST_CHECK(memcmp(qryptext_fprintf_fptr, &fprintf, sizeof(&fprintf)) != 0);

    qryptext_enable_fprintf();
    TEST_CHECK(qryptext_is_fprintf_enabled());
    TEST_CHECK(memcmp(qryptext_fprintf_fptr, &fprintf, sizeof(&fprintf)) == 0);

    qryptext_disable_fprintf();
}

static void qryptext_encrypt_null_args_fails()
{
    size_t olen;
    uint8_t tmp[4096];
    TEST_CHECK(QRYPTEXT_ERROR_NULL_ARG == qryptext_encrypt(NULL, 16, tmp, 4096, &olen, false, TEST_PUBLIC_KEY_KYBER1024));
    TEST_CHECK(QRYPTEXT_ERROR_NULL_ARG == qryptext_encrypt((uint8_t*)"TESTTESTTESTTEST", 16, NULL, 4096, &olen, false, TEST_PUBLIC_KEY_KYBER1024));
}

static void qryptext_encrypt_invalid_args_fails()
{
    size_t olen;
    uint8_t tmp[4096];
    TEST_CHECK(QRYPTEXT_ERROR_INVALID_ARG == qryptext_encrypt((uint8_t*)"TESTTESTTESTTEST", 0, tmp, 4096, &olen, false, TEST_PUBLIC_KEY_KYBER1024));
}

static void qryptext_encrypt_insufficient_output_buffer_size_fails()
{
    size_t olen;
    uint8_t tmp[512];
    TEST_CHECK(QRYPTEXT_ERROR_INSUFFICIENT_OUTPUT_BUFFER_SIZE == qryptext_encrypt((uint8_t*)"TESTTESTTESTTEST", 16, tmp, 512, &olen, false, TEST_PUBLIC_KEY_KYBER1024));
}

static void qryptext_decrypt_null_args_fails()
{
    size_t olen;
    uint8_t tmp[4096];
    TEST_CHECK(QRYPTEXT_ERROR_NULL_ARG == qryptext_decrypt((uint8_t*)"testtesttesttest", 16, false, NULL, 4096, &olen, TEST_SECRET_KEY_KYBER1024));
    TEST_CHECK(QRYPTEXT_ERROR_NULL_ARG == qryptext_decrypt(NULL, 16, false, tmp, 4096, &olen, TEST_SECRET_KEY_KYBER1024));
}

static void qryptext_decrypt_invalid_args_fails()
{
    size_t olen;
    uint8_t tmp[4096];
    TEST_CHECK(QRYPTEXT_ERROR_INVALID_ARG == qryptext_decrypt((uint8_t*)"testtesttesttest", 16, false, tmp, 4096, &olen, TEST_SECRET_KEY_KYBER1024));
    TEST_CHECK(QRYPTEXT_ERROR_INVALID_ARG == qryptext_decrypt((uint8_t*)"testtesttesttest", 4096, false, tmp, 0, &olen, TEST_SECRET_KEY_KYBER1024));
}

static void qryptext_decrypt_insufficient_output_buffer_size_fails()
{
    size_t olen;
    uint8_t tmp[512];
    TEST_CHECK(QRYPTEXT_ERROR_INSUFFICIENT_OUTPUT_BUFFER_SIZE == qryptext_decrypt((uint8_t*)"testtesttesttest", 4096, false, tmp, 16, &olen, TEST_SECRET_KEY_KYBER1024));
}

static void qryptext_hexstr2bin_invalid_args_returns_1()
{
    char hex[] = "90b008b752871710f032e58396eb75ead53b4abd83e074a855e8ca4c5fef4de7bb5e6a191cc10132466dbaee16a031c0046ce38535b8f922b93edd5e"
                 "429bcae7d715820107304e8e62818280cf643434e307d85dd659245e9a5588d93c5b62f34713e00b22d5c531f544de2b81879248b3d4e9b1160a60b9"
                 "b9670ff48a474c53057a02eeeefbbf16e384a252773502c2bc0a6c3f9831d20e2406a1f099567cab66cf7d61e8520995f3efecc0cfc0a4c667fdf0df"
                 "a5a4c56217e541ad4141642b00eab1095ad84721baac4fc9d9b86e47782e5ebc3d238885e4068ecea40ee2736aff024d5f4da58962b236b7c576ed57"
                 "1b9e3a0fb9ecfd9f877a530d11beecba0f938853c7dadde5";

    unsigned char bin[1024];
    size_t binlen;

    TEST_CHECK(1 == qryptext_hexstr2bin(NULL, 0, NULL, 0, NULL));
    TEST_CHECK(1 == qryptext_hexstr2bin(hex, 0, bin, sizeof(bin), NULL));
    TEST_CHECK(1 == qryptext_hexstr2bin(NULL, 20, bin, sizeof(bin), NULL));
    TEST_CHECK(1 == qryptext_hexstr2bin(hex, sizeof(hex), NULL, 0, &binlen));
}

static void qryptext_hexstr2bin_hexlen_odd_number_fails_returns_2()
{
    char hex[] = "f5c2351c941cbba29313771c84693dacb80f21be8bcb07406217ee3a07143e2a8fdbccd083d045a2818858c2faf72e58ec7e006a1386361c";

    unsigned char bin[128];
    size_t binlen;

    TEST_CHECK(2 == qryptext_hexstr2bin(hex, strlen(hex) - 1, bin, sizeof(bin), &binlen));
    TEST_CHECK(2 == qryptext_hexstr2bin(hex, sizeof(hex) - 2, bin, sizeof(bin), &binlen));
}

static void qryptext_hexstr2bin_insufficient_output_buffer_size_fails_returns_3()
{
    char hex[] = "f5c2351c941cbba29313771c84693dacb80f21be8bcb07406217ee3a07143e2a8fdbccd083d045a2818858c2faf72e58ec7e006a1386361c";

    unsigned char bin[1024];
    size_t binlen;

    TEST_CHECK(3 == qryptext_hexstr2bin(hex, strlen(hex), bin, 32, &binlen));
    TEST_CHECK(3 == qryptext_hexstr2bin(hex, strlen(hex), bin, strlen(hex) / 2, &binlen));
}

static void qryptext_hexstr2bin_succeeds_both_with_and_without_nul_terminator()
{
    char hex[] = "f5c2351c941cbba29313771c84693dacb80f21be8bcb07406217ee3a07143e2a8fdbccd083d045a2818858c2faf72e58ec7e006a1386361c";

    unsigned char bin[1024];
    size_t binlen;

    TEST_CHECK(0 == qryptext_hexstr2bin(hex, 112, bin, sizeof(bin), &binlen));
    TEST_CHECK(0 == qryptext_hexstr2bin(hex, 113, bin, sizeof(bin), &binlen));
}

static void qryptext_bin2hexstr_succeeds_output_length_double_the_input_length()
{
    unsigned char bin[] = { 0x0001, 0x0A, 0xB3, 0x71, 0x99, 0x4F, 0x8A, 0x11 };

    char hexstr[128];
    size_t hexstr_length;

    TEST_CHECK(0 == qryptext_bin2hexstr(bin, sizeof(bin), hexstr, sizeof(hexstr), &hexstr_length, true));
    TEST_CHECK(hexstr_length == sizeof(bin) * 2);
    TEST_CHECK(hexstr[hexstr_length] == '\0');
}

static void qryptext_bin2hexstr_null_or_invalid_args_fails_returns_1()
{
    unsigned char bin[] = { 0x0001, 0x0A, 0xB3, 0x71, 0x99, 0x4F, 0x8A, 0x11 };

    char hexstr[128];
    size_t hexstr_length;

    TEST_CHECK(1 == qryptext_bin2hexstr(NULL, sizeof(bin), hexstr, sizeof(hexstr), &hexstr_length, true));
    TEST_CHECK(1 == qryptext_bin2hexstr(bin, 0, hexstr, sizeof(hexstr), &hexstr_length, true));
    TEST_CHECK(1 == qryptext_bin2hexstr(bin, sizeof(bin), NULL, sizeof(hexstr), &hexstr_length, true));
}

static void qryptext_bin2hexstr_insufficient_output_buffer_size_returns_2()
{
    unsigned char bin[] = { 0x0001, 0x0A, 0xB3, 0x71, 0x99, 0x4F, 0x8A, 0x11 };

    char hexstr[128];
    size_t hexstr_length;

    TEST_CHECK(2 == qryptext_bin2hexstr(bin, sizeof(bin), hexstr, 6, &hexstr_length, true));

    // Double the size of the binary array should actually be enough,
    // but it's actually 1 byte too short: never forget to allocate +1 to allow for the NUL-terminator to fit in there!
    TEST_CHECK(2 == qryptext_bin2hexstr(bin, sizeof(bin), hexstr, sizeof(bin) * 2, &hexstr_length, true));
}

static void qryptext_bin2hexstr_success_returns_0()
{
    unsigned char bin[] = { 0x0001, 0x0A, 0xB3, 0x71, 0x99, 0x4F, 0x8A, 0x11 };

    char hexstr[128];
    size_t hexstr_length = 0;

    TEST_CHECK(0 == qryptext_bin2hexstr(bin, sizeof(bin), hexstr, sizeof(hexstr), NULL, true));

    // If output length pointer arg is omitted (passed NULL), the variable should be left untouched indeed!
    TEST_CHECK(hexstr_length == 0);

    TEST_CHECK(0 == qryptext_bin2hexstr(bin, sizeof(bin), hexstr, (sizeof(bin) * 2) + 1, &hexstr_length, true));

    // output string is NUL-terminated (which is why (sizeof(bin) * 2) + 1 bytes need to be allocated), but the NUL-terminator is not counted in the output length.
    // The output length of a binary array converted to hex string is always sizeof(bin) * 2

    TEST_CHECK(sizeof(bin) * 2 == hexstr_length);
}

static void qryptext_generate_kyber1024_keypair_NULL_args_returns_QRYPTEXT_ERROR_NULL_ARG()
{
    TEST_CHECK(QRYPTEXT_ERROR_NULL_ARG == qryptext_kyber1024_generate_keypair(NULL));
}

static void qryptext_generate_falcon1024_keypair_NULL_args_returns_QRYPTEXT_ERROR_NULL_ARG()
{
    TEST_CHECK(QRYPTEXT_ERROR_NULL_ARG == qryptext_falcon1024_generate_keypair(NULL));
}

static void qryptext_encrypt_raw_binary_decrypts_successfully()
{
    int r;
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length;
    size_t decrypted_string_length;

    //

    

    encrypted_string_length = qryptext_calc_encryption_output_length(TEST_STRING_LENGTH);
    encrypted_string = calloc(encrypted_string_length, sizeof(uint8_t));

    r = qryptext_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH, encrypted_string, encrypted_string_length, NULL, false, TEST_PUBLIC_KEY_KYBER1024);
    TEST_CHECK(0 == r);
    TEST_CHECK(0 != memcmp(TEST_STRING, encrypted_string, TEST_STRING_LENGTH));

    decrypted_string = calloc(encrypted_string_length, sizeof(uint8_t));
    r = qryptext_decrypt(encrypted_string, encrypted_string_length, false, decrypted_string, encrypted_string_length, &decrypted_string_length, TEST_SECRET_KEY_KYBER1024);
    TEST_CHECK(0 == r);

    TEST_CHECK(0 == memcmp(TEST_STRING, decrypted_string, TEST_STRING_LENGTH));
    TEST_CHECK(TEST_STRING_LENGTH == decrypted_string_length);

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void qryptext_encrypt_base64_decrypts_successfully()
{
    int r;
    uint8_t* encrypted_string = NULL;
    uint8_t* decrypted_string = NULL;
    size_t encrypted_string_length;
    size_t decrypted_string_length;

    //

    

    encrypted_string_length = qryptext_calc_base64_length(qryptext_calc_encryption_output_length(TEST_STRING_LENGTH));
    encrypted_string = calloc(encrypted_string_length, sizeof(uint8_t));

    r = qryptext_encrypt((uint8_t*)TEST_STRING, TEST_STRING_LENGTH, encrypted_string, encrypted_string_length, NULL, true, TEST_PUBLIC_KEY_KYBER1024);
    TEST_CHECK(0 == r);

    decrypted_string = calloc(encrypted_string_length, sizeof(uint8_t));
    r = qryptext_decrypt(encrypted_string, encrypted_string_length, true, decrypted_string, encrypted_string_length, &decrypted_string_length, TEST_SECRET_KEY_KYBER1024);
    TEST_CHECK(0 == r);

    TEST_CHECK(0 == memcmp(TEST_STRING, decrypted_string, TEST_STRING_LENGTH));
    TEST_CHECK(TEST_STRING_LENGTH == decrypted_string_length);

    //

    free(encrypted_string);
    free(decrypted_string);
}

static const qryptext_kyber1024_secret_key INVALID_KEY = { .hexstring = "Just something that isn't quite a key..." };

static void qryptext_encrypt_bin_decrypt_with_invalid_key_fails()
{
    unsigned char* encrypted_string = NULL;
    unsigned char* decrypted_string = NULL;
    size_t encrypted_string_length;
    size_t decrypted_string_length;

    //

    encrypted_string_length = qryptext_calc_encryption_output_length(strlen(TEST_STRING));
    encrypted_string = malloc(encrypted_string_length);
    memset(encrypted_string, 0x00, encrypted_string_length);

    TEST_CHECK(0 == qryptext_encrypt((unsigned char*)TEST_STRING, strlen(TEST_STRING), encrypted_string, encrypted_string_length, &encrypted_string_length, false, TEST_PUBLIC_KEY_KYBER1024));

    decrypted_string = malloc(encrypted_string_length);
    memset(decrypted_string, 0x00, encrypted_string_length);

    TEST_CHECK(0 != qryptext_decrypt(encrypted_string, encrypted_string_length, false, decrypted_string, encrypted_string_length, &decrypted_string_length, INVALID_KEY));
    TEST_CHECK(0 != memcmp(TEST_STRING, decrypted_string, TEST_STRING_LENGTH));
    //

    free(encrypted_string);
    free(decrypted_string);
}

static const qryptext_kyber1024_secret_key INVALID_KEY2 = { .hexstring = "¨^$#%c0a8e8607ad0730a10c0373c76439870dd8493ab8e91411b2559f90a0a14145d3452135f3688abba5e754cbd6746be9ca802ff3c799eb69c55242"
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

static void qryptext_encrypt_bin_decrypt_with_invalid_key_2_fails()
{
    unsigned char* encrypted_string = NULL;
    unsigned char* decrypted_string = NULL;
    size_t encrypted_string_length;
    size_t decrypted_string_length;

    //

    encrypted_string_length = qryptext_calc_encryption_output_length(strlen(TEST_STRING));
    encrypted_string = malloc(encrypted_string_length);
    memset(encrypted_string, 0x00, encrypted_string_length);

    TEST_CHECK(0 == qryptext_encrypt((unsigned char*)TEST_STRING, strlen(TEST_STRING), encrypted_string, encrypted_string_length, NULL, false, TEST_PUBLIC_KEY_KYBER1024));

    decrypted_string = malloc(encrypted_string_length);
    memset(decrypted_string, 0x00, encrypted_string_length);

    TEST_CHECK(0 != qryptext_decrypt(encrypted_string, encrypted_string_length, false, decrypted_string, encrypted_string_length, &decrypted_string_length, INVALID_KEY2));
    TEST_CHECK(0 != memcmp(TEST_STRING, decrypted_string, TEST_STRING_LENGTH));
    //

    free(encrypted_string);
    free(decrypted_string);
}

static void qryptext_encrypt_bin_decrypt_with_wrong_key_fails()
{
    unsigned char* encrypted_string = NULL;
    unsigned char* decrypted_string = NULL;
    size_t encrypted_string_length;
    size_t decrypted_string_length;

    //

    encrypted_string_length = qryptext_calc_encryption_output_length(strlen(TEST_STRING));
    encrypted_string = malloc(encrypted_string_length);
    memset(encrypted_string, 0x00, encrypted_string_length);

    TEST_CHECK(0 == qryptext_encrypt((unsigned char*)TEST_STRING, strlen(TEST_STRING), encrypted_string, encrypted_string_length, NULL, false, TEST_PUBLIC_KEY_KYBER1024));

    decrypted_string = malloc(encrypted_string_length);
    memset(decrypted_string, 0x00, encrypted_string_length);

    TEST_CHECK(0 != qryptext_decrypt(encrypted_string, encrypted_string_length, false, decrypted_string, encrypted_string_length, &decrypted_string_length, TEST_SECRET_KEY_KYBER1024_ALT));
    TEST_CHECK(0 != memcmp(TEST_STRING, decrypted_string, TEST_STRING_LENGTH));

    qryptext_kyber1024_keypair kyber1024_keypair;
    int r = qryptext_kyber1024_generate_keypair(&kyber1024_keypair);
    TEST_CHECK(r == 0);

    TEST_CHECK(0 != qryptext_decrypt(encrypted_string, encrypted_string_length, false, decrypted_string, encrypted_string_length, &decrypted_string_length, kyber1024_keypair.secret_key));
    TEST_CHECK(0 != memcmp(TEST_STRING, decrypted_string, TEST_STRING_LENGTH));

    //

    free(encrypted_string);
    free(decrypted_string);
}

static void qryptext_sign_verify_signature_base64_successful()
{
    uint8_t signature[4096];
    size_t signature_length;

    int r = qryptext_sign((uint8_t*)TEST_STRING, strlen(TEST_STRING), signature, 4096, &signature_length, true, TEST_SECRET_KEY_FALCON1024);
    TEST_CHECK(r == 0);

    r = qryptext_verify((uint8_t*)TEST_STRING, strlen(TEST_STRING), signature, signature_length, true, TEST_PUBLIC_KEY_FALCON1024);
    TEST_CHECK(r == 0);
}

static void qryptext_sign_verify_signature_base64_wrong_key_fails()
{
    uint8_t signature[4096];
    size_t signature_length;

    int r = qryptext_sign((uint8_t*)TEST_STRING, strlen(TEST_STRING), signature, 4096, &signature_length, true, TEST_SECRET_KEY_FALCON1024);
    TEST_CHECK(r == 0);

    r = qryptext_verify((uint8_t*)TEST_STRING, strlen(TEST_STRING), signature, signature_length, true, TEST_PUBLIC_KEY_FALCON1024_ALT);
    TEST_CHECK(r != 0);
}

static void qryptext_sign_verify_signature_bin_successful()
{
    uint8_t signature[4096];
    size_t signature_length;

    int r = qryptext_sign((uint8_t*)TEST_STRING, strlen(TEST_STRING), signature, 4096, &signature_length, false, TEST_SECRET_KEY_FALCON1024);
    TEST_CHECK(r == 0);

    r = qryptext_verify((uint8_t*)TEST_STRING, strlen(TEST_STRING), signature, signature_length, false, TEST_PUBLIC_KEY_FALCON1024);
    TEST_CHECK(r == 0);
}

static void qryptext_sign_verify_signature_bin_wrong_key_fails()
{
    uint8_t signature[4096];
    size_t signature_length;

    int r = qryptext_sign((uint8_t*)TEST_STRING, strlen(TEST_STRING), signature, 4096, &signature_length, false, TEST_SECRET_KEY_FALCON1024);
    TEST_CHECK(r == 0);

    r = qryptext_verify((uint8_t*)TEST_STRING, strlen(TEST_STRING), signature, signature_length, false, TEST_PUBLIC_KEY_FALCON1024_ALT);
    TEST_CHECK(r != 0);

    r = qryptext_sign((uint8_t*)TEST_STRING, strlen(TEST_STRING), signature, 4096, &signature_length, false, TEST_SECRET_KEY_FALCON1024_ALT);
    TEST_CHECK(r == 0);

    qryptext_falcon1024_keypair falcon1024_keypair;
    r = qryptext_falcon1024_generate_keypair(&falcon1024_keypair);
    TEST_CHECK(r == 0);

    r = qryptext_verify((uint8_t*)TEST_STRING, strlen(TEST_STRING), signature, signature_length, false, falcon1024_keypair.public_key);
    TEST_CHECK(r != 0);
}

static void qryptext_sign_NULL_arg_fails()
{
    uint8_t signature[4096];
    size_t signature_length;
    TEST_CHECK(QRYPTEXT_ERROR_NULL_ARG == qryptext_sign(NULL, 16, signature, sizeof signature, &signature_length, false, TEST_SECRET_KEY_FALCON1024));
    TEST_CHECK(QRYPTEXT_ERROR_NULL_ARG == qryptext_sign((uint8_t*)"testtesttesttest", 16, NULL, sizeof signature, &signature_length, false, TEST_SECRET_KEY_FALCON1024));
    TEST_CHECK(QRYPTEXT_ERROR_NULL_ARG == qryptext_sign((uint8_t*)"testtesttesttest", 16, signature, sizeof signature, NULL, false, TEST_SECRET_KEY_FALCON1024));
}

static void qryptext_sign_INVALID_arg_fails()
{
    uint8_t signature[4096];
    size_t signature_length;
    TEST_CHECK(QRYPTEXT_ERROR_INVALID_ARG == qryptext_sign((uint8_t*)"testtesttesttest", 0, signature, sizeof signature, &signature_length, false, TEST_SECRET_KEY_FALCON1024));
}

static void qryptext_sign_insufficient_output_buffer_size_fails()
{
    uint8_t signature[4096];
    size_t signature_length;
    TEST_CHECK(QRYPTEXT_ERROR_INSUFFICIENT_OUTPUT_BUFFER_SIZE == qryptext_sign((uint8_t*)"testtesttesttest", 16, signature, 16, &signature_length, false, TEST_SECRET_KEY_FALCON1024));
    TEST_CHECK(QRYPTEXT_ERROR_INSUFFICIENT_OUTPUT_BUFFER_SIZE == qryptext_sign((uint8_t*)"testtesttesttest", 16, signature, OQS_SIG_falcon_1024_length_signature, &signature_length, true, TEST_SECRET_KEY_FALCON1024));
}

static void qryptext_verify_signature_NULL_arg_fails()
{
    uint8_t signature[4096];
    size_t signature_length;

    int r = qryptext_sign((uint8_t*)TEST_STRING, strlen(TEST_STRING), signature, 4096, &signature_length, false, TEST_SECRET_KEY_FALCON1024);
    TEST_CHECK(r == 0);

    TEST_CHECK(QRYPTEXT_ERROR_NULL_ARG == qryptext_verify(NULL, strlen(TEST_STRING), signature, signature_length, false, TEST_PUBLIC_KEY_FALCON1024));
    TEST_CHECK(QRYPTEXT_ERROR_NULL_ARG == qryptext_verify((uint8_t*)TEST_STRING, strlen(TEST_STRING), NULL, signature_length, false, TEST_PUBLIC_KEY_FALCON1024));
}

static void qryptext_verify_signature_INVALID_arg_fails()
{
    uint8_t signature[4096];
    size_t signature_length;

    int r = qryptext_sign((uint8_t*)TEST_STRING, strlen(TEST_STRING), signature, 4096, &signature_length, false, TEST_SECRET_KEY_FALCON1024);
    TEST_CHECK(r == 0);

    TEST_CHECK(QRYPTEXT_ERROR_INVALID_ARG == qryptext_verify((uint8_t*)TEST_STRING, 0, signature, signature_length, false, TEST_PUBLIC_KEY_FALCON1024));
}

TEST_LIST = {
    { "null_test_success", null_test_success }, //
    // -----------------------------------------------------------
    { "qryptext_encrypt_null_args_fails", qryptext_encrypt_null_args_fails }, //
    { "qryptext_fprintf_enables_and_disables_correctly", qryptext_fprintf_enables_and_disables_correctly }, //
    { "qryptext_encrypt_invalid_args_fails", qryptext_encrypt_invalid_args_fails }, //
    { "qryptext_encrypt_insufficient_output_buffer_size_fails", qryptext_encrypt_insufficient_output_buffer_size_fails }, //
    { "qryptext_decrypt_null_args_fails", qryptext_decrypt_null_args_fails }, //
    { "qryptext_decrypt_invalid_args_fails", qryptext_decrypt_invalid_args_fails }, //
    { "qryptext_decrypt_insufficient_output_buffer_size_fails", qryptext_decrypt_insufficient_output_buffer_size_fails }, //
    { "qryptext_hexstr2bin_invalid_args_returns_1", qryptext_hexstr2bin_invalid_args_returns_1 }, //
    { "qryptext_hexstr2bin_hexlen_odd_number_fails_returns_2", qryptext_hexstr2bin_hexlen_odd_number_fails_returns_2 }, //
    { "qryptext_hexstr2bin_insufficient_output_buffer_size_fails_returns_3", qryptext_hexstr2bin_insufficient_output_buffer_size_fails_returns_3 }, //
    { "qryptext_hexstr2bin_succeeds_both_with_and_without_nul_terminator", qryptext_hexstr2bin_succeeds_both_with_and_without_nul_terminator }, //
    { "qryptext_bin2hexstr_succeeds_output_length_double_the_input_length", qryptext_bin2hexstr_succeeds_output_length_double_the_input_length }, //
    { "qryptext_bin2hexstr_null_or_invalid_args_fails_returns_1", qryptext_bin2hexstr_null_or_invalid_args_fails_returns_1 }, //
    { "qryptext_bin2hexstr_insufficient_output_buffer_size_returns_2", qryptext_bin2hexstr_insufficient_output_buffer_size_returns_2 }, //
    { "qryptext_bin2hexstr_success_returns_0", qryptext_bin2hexstr_success_returns_0 }, //
    { "qryptext_generate_kyber1024_keypair_NULL_args_returns_QRYPTEXT_ERROR_NULL_ARG", qryptext_generate_kyber1024_keypair_NULL_args_returns_QRYPTEXT_ERROR_NULL_ARG }, //
    { "qryptext_generate_falcon1024_keypair_NULL_args_returns_QRYPTEXT_ERROR_NULL_ARG", qryptext_generate_falcon1024_keypair_NULL_args_returns_QRYPTEXT_ERROR_NULL_ARG }, //
    { "qryptext_encrypt_raw_binary_decrypts_successfully", qryptext_encrypt_raw_binary_decrypts_successfully }, //
    { "qryptext_encrypt_base64_decrypts_successfully", qryptext_encrypt_base64_decrypts_successfully }, //
    { "qryptext_encrypt_bin_decrypt_with_invalid_key_fails", qryptext_encrypt_bin_decrypt_with_invalid_key_fails }, //
    { "qryptext_encrypt_bin_decrypt_with_invalid_key_2_fails", qryptext_encrypt_bin_decrypt_with_invalid_key_2_fails }, //
    { "qryptext_sign_verify_signature_base64_successful", qryptext_sign_verify_signature_base64_successful }, //
    { "qryptext_sign_verify_signature_base64_wrong_key_fails", qryptext_sign_verify_signature_base64_wrong_key_fails }, //
    { "qryptext_sign_verify_signature_bin_successful", qryptext_sign_verify_signature_bin_successful }, //
    { "qryptext_sign_verify_signature_bin_wrong_key_fails", qryptext_sign_verify_signature_bin_wrong_key_fails }, //
    { "qryptext_encrypt_bin_decrypt_with_wrong_key_fails", qryptext_encrypt_bin_decrypt_with_wrong_key_fails }, //
    { "qryptext_sign_NULL_arg_fails", qryptext_sign_NULL_arg_fails }, //
    { "qryptext_sign_INVALID_arg_fails", qryptext_sign_INVALID_arg_fails }, //
    { "qryptext_sign_insufficient_output_buffer_size_fails", qryptext_sign_insufficient_output_buffer_size_fails }, //
    { "qryptext_verify_signature_NULL_arg_fails", qryptext_verify_signature_NULL_arg_fails }, //
    { "qryptext_verify_signature_INVALID_arg_fails", qryptext_verify_signature_INVALID_arg_fails }, //
    // -----------------------------------------------------------
    { NULL, NULL } //
};

#undef TEST_STRING_LENGTH
