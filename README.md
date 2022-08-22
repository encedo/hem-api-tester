hem-api-tester
=======

A set of scripts, one per functionality, to test Encedo HEM API. The tests are a part of the Common Criteria certification procedure.


Using
=====

1. Download the Ubuntu 22.04 (recommended) ISO image, flash the USB stick and boot the PC from the stick. Link: https://ubuntu.com/download/desktop 

2. Select 'Try Ubuntu" to start a fresh Ubuntu instance and get a desktop.

3. Get connected to the Internet (set WiFi or wired connection).

3. Upgrade the system and install the required packages. Open `terminal` and type:

   `sudo apt update`
   
   `sudo apt upgrade`
   
   `sudo apt install git php-cli`

4. Clone this repository.

   `git clone git@github.com:encedo/hem-api-tester.git`
   
   `cd hem-api-tester`

5. Run first test.

   `php test_1.php`

Cheers :)
