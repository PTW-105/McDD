###################################
# Title: McAfee Debug & Diag Tool
# Version: 0.1a
# Author: Josh Stemp
# Contact: jstemp105@gmail.com
# Copyright Joshua Stemp 2015
###################################

# McAfee Product Terminology:
# ePO/EPO = ePolicy Orchestrator
# MA = McAfee Agent
# VSE = VirusScan Enterprise
# VSES = VirusScan Enterprise for Storage
# HIPS = Host Intrusion Prevention System


# TO-DO's:
# TODO: Change log collection functions to instantiated class objects
# TODO: Implement function repeat functionality
# TODO: Setup default options for all user prompts

# IMPORTS
import os
import subprocess
import sys
import getpass
from distutils import dir_util


# GLOBAL VARIABLES
os_version = ""
os_arch = ""
installed_products = []
central_log_path = "C:\McDD_Logs"
hostname = ""


# FUNCTIONS
def system_online(started_by_function):
    global hostname
    global system_pingable

    print("Loaded system_online function!")
    hostname = str(raw_input("Hostname/IP: "))  # TODO: Implement multiple hostnames/IPs & .txt lists of hostnames/IPs
    output = subprocess.Popen(["ping.exe", hostname], stdout=subprocess.PIPE).communicate()[0]
    print(output)
    if 'unreachable' in output:
        system_pingable = False
        print("System seems to not be pingable")
    elif 'TTL' in output:
        system_pingable = True
        print("System seems to be online")
    elif 'Received = 4' in output\
            or 'Received = 3' in output\
            or 'Received = 2' in output\
            or 'Received = 1' in output:
        print("System seems to be online")
    elif 'could not find host' in output:
        system_pingable = False
        print("System name seems to not be resolvable")
    else:
        system_pingable = False
        print("System status seems to be unknown")

    # TODO: Implement socket based service discovery

    if started_by_function is True:
        return system_pingable, hostname
    else:
        exit_prompt()


def os_version_detection(started_by_function):
    global os_version
    global os_arch

    # Determine what family of Windows is installed.
    print("Loaded os_version_detection function!")
    print("Detecting family of Windows...")
    sys_info_raw = str(sys.getwindowsversion())
    if 'major=6, minor=2' in sys_info_raw:
        os_version = "Win8"
        print("Detected OS: Windows 8/2012!")
    elif 'major=6, minor=1' in sys_info_raw:
        os_version = "Win7"
        print("Detected OS: Windows 7/2008!")
    elif 'major=6, minor=0' in sys_info_raw:
        os_version = "WinVista"
        print("Detected OS: Windows Vista!")
    elif 'major=5, minor=2' in sys_info_raw:
        os_version = "Win2003"
        print("Detected OS: Windows 2003!")
    elif 'major=5, minor=1' in sys_info_raw:
        os_version = "WinXP"
        print("Detected OS: Windows XP!")
    else:
        os_version = "Unknown"
        print("Detected OS: Unknown!")
        print sys_info_raw

    # Determine if OS is x86 from x86_64 architecture.
    print("Detecting architecture...")
    sys_arch_raw = os.environ["PROCESSOR_ARCHITECTURE"]
    try:
        sys_arch_raw_w6432 = os.environ["PROCESSOR_ARCHITEW6432"]
    except KeyError:
        sys_arch_raw_w6432 = ""
        # sys_arch_raw_w6432 is assigned "" if PROCESSOR_ARCHITEW6432 doesn't exist.
    if (sys_arch_raw == "x86" and sys_arch_raw_w6432 == "AMD64") or sys_arch_raw == "AMD64":
        os_arch = 64
        print("Detected Architecture: x86_64!")
    elif sys_arch_raw == "x86":
        os_arch = 32
        print("Detected Architecture: x86!")
    else:
        os_arch = "Unknown"
        print("Detected Architecture: Unknown!")
        print(sys_arch_raw, sys_arch_raw_w6432)

    if started_by_function is True:
        return
    else:
        exit_prompt()


def installed_epo():
    global os_arch
    global installed_products

    if os_arch == 32:
        epo_path = "C:\Program Files\McAfee\ePolicy Orchestrator"
    elif os_arch == 64:
        epo_path = "C:\Program Files (x86)\McAfee\ePolicy Orchestrator"
    else:
        print("ERROR: EPO PATH UNKNOWN")
        raise

    print("Checking if ePO is installed...")
    if os.path.exists(epo_path) is True:  # TODO: Add version detection functionality & logging
        print("Detected ePO!")
        installed_products.append("ePO")
    elif os.path.exists(epo_path) is False:
        print("ePO not detected!")
        return
    else:
        print("ERROR: EPO PATH OTHER NON-BOOLEAN")
        raise


def installed_ma():
    global os_arch
    global installed_products

    if os_arch == 32:
        ma5_path = "C:\Program Files\McAfee\Agent"
        ma4x_path = "C:\Program Files\McAfee\Common Framework"
    elif os_arch == 64:
        ma5_path = "C:\Program Files\McAfee\Agent"
        ma4x_path = "C:\Program Files (x86)\McAfee\Common Framework"
    else:
        print("ERROR: MA PATH UNKNOWN")
        raise

    print("Checking if MA is installed...")
    if os.path.exists(ma5_path) is True:  # TODO: Add version detection functionality & logging
        print("Detected MA 5.0!")
        installed_products.append("MA50")
    elif os.path.exists(ma4x_path) is True:
        print("Detected MA 4.x!")
        installed_products.append("MA4x")
    elif os.path.exists(ma4x_path) is False and os.path.exists(ma5_path) is False:
        print("MA not detected!")
        return
    else:
        print("ERROR: MA PATH OTHER NON-BOOLEAN")
        raise


def installed_vse():
    global os_arch
    global installed_products

    if os_arch == 32:
        vse_path = "C:\Program Files\McAfee\VirusScan Enterprise"
    elif os_arch == 64:
        vse_path = "C:\Program Files (x86)\McAfee\VirusScan Enterprise"
    else:
        print("ERROR: VSE PATH UNKNOWN")
        raise

    print("Checking if VSE is installed...")
    if os.path.exists(vse_path) is True:  # TODO: Add version detection functionality & logging
        print("Detected VSE!")
        installed_products.append("VSE")
    elif os.path.exists(vse_path) is False:
        print("VSE not detected!")
        return
    else:
        print("ERROR: VSE PATH OTHER NON-BOOLEAN")
        raise


def installed_hips():
    global os_arch
    global installed_products

    if os_arch == 32:
        hips_path = "C:\Program Files\McAfee\Host Intrusion Prevention"
    elif os_arch == 64:
        hips_path = "C:\Program Files (x86)\McAfee\Host Intrusion Prevention"
    else:
        print("ERROR: VSE PATH UNKNOWN")
        raise

    print("Checking if HIPS is installed...")
    if os.path.exists(hips_path) is True:  # TODO: Add version detection functionality & logging
        print("Detected HIPS!")
        installed_products.append("HIPS")
    elif os.path.exists(hips_path) is False:
        print("HIPS not detected!")
        return
    else:
        print("ERROR: HIPS PATH OTHER NON-BOOLEAN")
        raise


def installed_product_detection():
    global os_version
    global os_arch
    global installed_products

    repeat = True
    while repeat is True:
        # Resetting all global vars to prevent contamination.
        os_version = ""
        os_arch = ""
        installed_products = []

        print("Loaded installed_product_detection function!")
        print("Loading os_version_detection function...")
        os_version_detection(True)
        installed_epo()
        installed_ma()
        installed_vse()
        installed_hips()

        print("\nThe following McAfee products were detected on this host:")
        if not installed_products:
            print("None")
        else:
            print(installed_products)

        repeat_prompt = raw_input("\nWould you like to run this again [y/n]: ")
        loop = True
        while loop is True:
            if repeat_prompt == 'y' or repeat_prompt == 'Y':
                loop = False
                repeat = True
            elif repeat_prompt == 'n' or repeat_prompt == 'N':
                loop = False
                repeat = False
                exit_prompt()
            else:
                loop = True
                print("Invalid input. Please try again.")


def log_collect_epo():
    return


def log_collect_ma():
    global installed_products
    global central_log_path

    if "MA50" in installed_products:
        print("Collecting MA50 logs...")
        try:
            # dir_util.copy_tree("%temp%\McAfeeLogs", central_log_path + "\MA5")
            # print("%TEMP% logs collected!")
            dir_util.copy_tree("C:\ProgramData\McAfee\Agent\logs", central_log_path + "\MA5\Data")
            print("MA50 logs collected!")
        except:
            print("ERROR: Could not copy MA50 logs!")

    elif "MA" in installed_products:
        print("Collecting MA logs...")
        try:
            dir_util.copy_tree("C:\ProgramData\McAfee\Common Framework", central_log_path + "\MA\Data")
            print("MA logs collected!")
        except:
            print("ERROR: Could not copy MA logs!")
    return


def log_collect_vse():
    global installed_products
    global central_log_path

    print("Collecting VSE logs...")
    if "VSE" in installed_products:
        try:
            print("Collecting VSE logs...")
            dir_util.copy_tree("C:\ProgramData\McAfee\DesktopProtection", central_log_path + "\VSE\Data")
            print("VSE logs collected!")
        except:
            print("ERROR: Could not copy VSE logs!")
    return


def log_collect_hips():
    global installed_products
    global central_log_path

    print("Collecting HIPS logs...")
    if "HIPS" in installed_products:
        try:
            print("Collecting HIPS logs...")
            dir_util.copy_tree("C:\ProgramData\McAfee\Host Intrusion Prevention", central_log_path + "\HIPS\Data")
            print("HIPS logs collected!")
        except:
            print("ERROR: Could not copy HIPS logs!")
    return


def log_collection():
    print("Loaded log_collection function!")
    log_collect_ma()
    log_collect_vse()
    log_collect_hips()

    exit_prompt()


def remote_shell():
    global hostname
    global system_pingable
    username = ""
    password = ""

    print("Loaded remote_shell function!")
    system_pingable = False
    system_online(True)
    if system_pingable is False:
        prompt = raw_input("This system does not appear to be pingable. Continue [y/n]:")
        loop = True
        while loop is True:
            if prompt == 'y' or prompt == 'Y':
                loop = False
                print("Continuing...")
            elif prompt == 'n' or prompt == 'N':
                loop = False
                exit_prompt()
            else:
                loop = True
                print("Invalid input. Please try again.")
    username = raw_input("Input username [DOMAIN\username]: ")
    password = getpass.getpass("Input password: ")
    try:
        print("Connecting to {0} with PSExec...").format(hostname)
        command = "tools\PSExec.exe \\\\{0} -u {1} -p {2} -accepteula cmd".format(hostname, username, password)
        os.system(command)
    except:
        print("Unable to connect to {0} with PSExec!").format(hostname)

    exit_prompt()


def exit_prompt():
    return_menu = raw_input("\nWould you like to return to the menu [y/n]: ")
    loop = True
    while loop is True:
        if return_menu == 'y' or return_menu == 'Y':
            loop = False
            main_menu()
        elif return_menu == 'n' or return_menu == 'N':
            loop = False
            print("Exiting...")
            exit()
        else:
            loop = True
            print("Invalid input. Please try again.")


def main_menu():
    print """
    McAfee Debug & Diag Tool (McDD)
    v0.1a

    == McDD MAIN MENU ==

    -- Remote Tools --
    1. System Online Check
    2. # Remote Interactive Shell (incomplete)
    3. # Check Running McAfee Processes (incomplete)
    4. # Remote Software Uninstall (incomplete)
    5. #
    6. #

    -- Local Tools --
    7. Detect Operating System
    8. Detect Installed McAfee Products
    9. Collect All Product Logs
    10. #
    11. #
    12. #
    -----------------
    99. Exit
    """

    loop = True
    while loop is True:
        menu_option = input("Make a selection: ")
        # Remote Tools
        if menu_option == 1:
            loop = False
            print("Loading system_online function...")
            system_online(False)

        elif menu_option == 2:
            loop = False
            print("Loading remote_shell function...")
            remote_shell()

        elif menu_option == 3:
            loop = False

        elif menu_option == 4:
            loop = False

        elif menu_option == 5:
            loop = False

        elif menu_option == 6:
            loop = False

        # Local Tools
        elif menu_option == 7:
            loop = False
            print("Loading os_version_detection function...")
            os_version_detection(False)

        elif menu_option == 8:
            loop = False
            print("Loading installed_product_detection function...")
            installed_product_detection()

        elif menu_option == 9:
            loop = False
            print("Loading log_collection function...")
            log_collection()

        elif menu_option == 10:
            loop = False

        elif menu_option == 11:
            loop = False

        elif menu_option == 12:
            loop = False

        elif menu_option == 99:
            loop = False
            print("Exiting...")
            exit()

        else:
            loop = True
            print("Invalid input. Please try again.")

# EXECUTION
os.system('cls')
main_menu()