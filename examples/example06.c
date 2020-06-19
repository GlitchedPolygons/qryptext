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
#include <stdint.h>
#include <string.h>
#include <qryptext/util.h>
#include <qryptext/keygen.h>
#include <qryptext/sign.h>
#include <qryptext/verify.h>

static const char TEST_STRING[] = "You've proved yourself a decisive man, so I don't expect you'll have any trouble deciding what to do. "
                                  "If you're interested, just step into the portal and I will take that as a yes.";

static const qryptext_falcon1024_secret_key TEST_SECRET_KEY = { .hexstring = "5a093de0ffbff901df6c81e87c3283fc30862ff8400807f093610f044f17a107c24f7ffc207e2d8800ef3bff6fc1008dfff4c4e83e01ef830fba20fb"
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

static const qryptext_falcon1024_public_key TEST_PUBLIC_KEY = { .hexstring = "0aac4a3fe8e8db55b894e04385237a0dad26d5925b4c8da1a4bb88ce2154547db4ba8c76ac18d91507477c0bd9840ac751360c29208bc228641475bb"
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

int main(void)
{
    qryptext_enable_fprintf(); // Allow fprintf in case errors occur and need to be fprintf'ed.

    int r = -1;

    size_t signature_length;
    const size_t signature_buffer_size = qryptext_calc_base64_length(OQS_SIG_falcon_1024_length_signature);
    uint8_t* signature = calloc(signature_buffer_size, sizeof(uint8_t));
    if (signature == NULL)
    {
        printf("ERROR: Signing failed - OUT OF MEMORY!\n");
        goto exit;
    }

    const size_t TEST_STRING_LENGTH = strlen(TEST_STRING); // Here you can use strlen, because signing with or without NUL-terminator char makes no real difference.

    printf("\n---- QRYPTEXT ----\n--  Example 06  --\n\n");
    printf("Signing the following string:\n\n%s\n\n", TEST_STRING);

    // Here's how to sign a text message (allocating the input and output buffers on the stack) using qryptext's sign function.

    // When using stack-allocated buffers, don't forget to assign the output_length pointer to know how many bytes were written into the output_buffer.
    r = qryptext_sign((uint8_t*)TEST_STRING, TEST_STRING_LENGTH, signature, signature_buffer_size, &signature_length, true, TEST_SECRET_KEY);

    printf("Status code: %d\n\n", r);

    if (r != 0)
    {
        printf("ERROR: Signing failed! \"qryptext_sign\" returned: %d\n", r);
        goto exit;
    }

    printf("Signature >>> base64:\n\n%s\n\n", signature);

    r = qryptext_verify((uint8_t*)TEST_STRING, TEST_STRING_LENGTH, signature, signature_length, true, TEST_PUBLIC_KEY);

    printf("Status code: %d\n\n", r);

    if (r != 0)
    {
        printf("ERROR: Signature verification failed! \"qryptext_verify\" returned: %d\n", r);
        goto exit;
    }

    printf("Signature creation and verification successful!\n\n");

exit:
    // Cleanup:
    free(signature);
    qryptext_disable_fprintf();
    return r;
}
