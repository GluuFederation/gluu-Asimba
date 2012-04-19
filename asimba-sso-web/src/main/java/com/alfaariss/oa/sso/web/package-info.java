/*
 * Asimba Server
 * 
 * Copyright (C) 2012 Asimba
 * Copyright (C) 2007-2008 Alfa & Ariss B.V.
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see www.gnu.org/licenses
 * 
 * Asimba - Serious Open Source SSO - More information on www.asimba.org
 * 
 */

/**
 * Web based Authentication and SSO Components.
 * 
 * <pre>
 *        ....,7DMMD7?7OOO8D88M$DNON8MMMMMMNNM8ONNM$DMNMDMMMNNDDNMMMMDO8Z...............
 *        .....:NMNN8?IODO?MMMMMMDMDMDNMDNNMN88O88MD7NN8ODNNDNDDMDMMMMN$D8?. ..... ......
 *         ....IMNN$Z+$NMZOMNIMNN8NDNNNNMZ8OZOD8NMDNDODNDONNMNDD$Z8NMMM8ND8. . ........ .
 *       ....,.$NDM$7ONMMDMMMDND$NMMMND8D$O~O78MMNDDNMNDDD8MMMMO8OONMMMM8N8?.. ........ .
 *       ...+..8NZNMMDMMMNMMMM8ZIMMNMNINN7ODZ8MMNDN$ZNNNNNDDMMNNZDDMNMMNN8N$ . . . . .. .
 *       ..?.7?=$NMMMNMMNNMMMNM8$MDMNZ7DDDONNMMMN8Z$MMNMMMMMMMMMMNMNMNNMMNMD.............
 *       ..~==88ZMMM8NDMMMMMMMN8MMDMD$7$DDNMMMM8DODDMMMMMNMMMMMMMMMNMMMMMMMN7.  .........
 *       .:.ONDMNNMDO8MMNMMMMNM88DMMN=IZ8NZ7MMDN?M8MMMMMMMMMMMMMMMMNMMMMMM8N$,.... . .. .
 *       ..I:NMMMMNMMMDMNNMMMMMDNMNM7=IM$+~+ZMNOOZ+MMMMMMMMNMMMMMMMMMMMMMMMMD$...........
 *       =Z:.?DNMM8NMM8NNN8DNMNMNNNOI8N7+:=7Z788NMDMMMMMMNMNMMMMMMNMMMMMMMN$MD.... .... .
 *       .,M$NMMMDMMMOMZMMMMMMD8MO?$$OZ=~=?7+==+ZODOMMMMMMMMMMMMMMNNONMMNNM.:DN... ......
 *       ..,NNZNM8MMMNMMNMMMMNZ7$I+I$I$$7$7+~~~:~?7$8MMMMNNMMMMMMNNOMMMMMMMM.~8,.. . ..  
 *       ...INODNNMMDMMMMMMMM8Z7$7OOZ88D8$?=~~~~+Z8DNMNMNMMMMMMMNNMMMMMMMMMMMM87.........
 *       ..O$D8OO$MMMNNMMMMMDOOOOMMMMMMMDOI=~~=?ONMMMMMMMMMMMNMMMMNMMMMMMMMMMMMN.........
 *       ..~MDD8NOZMMMMMMMMMZM$++Z7:8DOID8O~:~=8MMMONNNODMMMDMMMDMNMMMMMMMMMMMNM.. . .   
 *       =DNMNONODO8DDMMMMMDND~:::=+=???~~+:,:+NNO777$ZZDZ$$ZDMMMDMMMMMMMMMMMMMM.. .... .
 *       ..NDNODDZD8MMMMNMMMM?,,,,::::::::~:,~IZ+~::~~~===+?7OMMMMMMMMMMMMMMMMMM~.. ... .
 *       ..NDMD8MMMDNDODMNMMM?::,,,:::,,:~::,~I?+=~::~~~~==I$8NMNDMMMMMMMMMMMMM.N?~  .. .
 *       ..DODDDMMMMNMMMNMMMM+~:::::::,,:~~::~II+=~~~~~=~=?7ZDNMMMMMMMMMMMMMNM+N.Z.......
 *       ..8,IO8NMMM8ZZDMMMMM+=~:::::::::~~:,~+$?7~~~~~~~+?$ODMNNMMMMMMMMMNMMDM.D.7......
 *       ..+?..DNMMNMNNMMMMMNI~~~~~:::::~:~:,~+?+Z~~~=~==?7O8NMMMMMMMMMMMMMMMMM:.N..... .
 *       ...N.,DMMMMMMMMMMMMN?=~~~::::::78$=~~$O8Z=~~~~++7Z88MMMMMMMMMMMMMNDMMM:.?=$.....
 *       .+:ZDNMNMMMMMMMMMMMM=+=~~::::::~+:=DOMMMNI:~~=?IZODNNMMMMMMMMMDMM7D8MM.I?=....  
 *       ...,O8$:MMMMMNMMMMMM+==+~~::::::=~~?7?ZI?~~~~+I7ODM8DMMMMMMMMMMN8O$O8I,N:....  .
 *       I.,?+OMMMMMMMMMMMMMM7~=?=~~~~:::::::,:~==~~=+I$ZNND8NMMMMMMNMMMMD8DD,8M=:..... .
 *       .,ZOO88NMDMMMMMMMMMMM+=+?==~~~:+O8$+=ONDI+?IIZO8NN8DMMMMMMMMMMNMNNNNN8O......   
 *       .:,7?D8NMMNN8MMMMMMMMM+=??+++~:~~::,=:~====7ZO8NNDDNMMMMMMNDDMNNNNNNM=... ......
 *       ...D8NDNNNZDMMMMM8MMMMM7+?7?=~=~~~~~~=+I$OO$Z8DNDDDMMMMMMMM8MDMMMMM~8...........
 *        ...NN8ODDDMMD:MMMMMMMMMOI+I?I?IONMMMMMMM8OODNNNDMMMMMMMMMMMMNDMM8N.... . ......
 *        . ..:~NMMMMMM8MMMMMOMMMO8$?===~:~:~?+II++?$ODNNMMMMMMMMMMMMMNI~DM... ..........
 *       ...........ZNM=MMMMMNOMM8ZO8?+=~~~~~~===+77O8NMMMMMMMMMMMMMMMMMMDO,......?7=~~~~
 *       ....  .  ...MMMMMMM88ZMMD$7$OI?+=++???I+7$ODNMMMMMMMMMMMMMMMMMMND.....OZI=~~~:::
 *       ....  ......MMNMMMN8DOMMMIII7ZDOOOZZOOOODDNMMMMMMMMMNMMMMMMMMMMM+...D87~~:::::::
 *       ...... .. .??MMMMMMMN$MMM??+?I$8NMMMMMMMMMMMMMMMMMNDDNMMMMMMMMMMMM8DZ+~:::::,,,:
 *       ~~=...........ZMMM8MD.8MM$==++?$8NMMMMMMMMMMMMMMMD8OO8DDNMMMNNMMMMN$+~:::::,,,,,
 *       :::~~~~,.........DDNMNMDN?==~=+?7ODNNNMMMMMMMMMM8OZZZZZOMZZ88MMNO7+~::::::,:,,::
 *       :,::::~~+?I7?.......+MNDO=~=~~~=?7Z8DNMMMMMMMMDOZZ$$$$$~Z$7$$+=~:::::~~::::,,,,,
 *       ,,,::::~~===?7Z+..$MMN8NZ=~=~~~~=+I$O88DNNNM8OZ$$$7$$7I7IIIII?======~:::::::,:::
 * </pre>
 */
package com.alfaariss.oa.sso.web;
