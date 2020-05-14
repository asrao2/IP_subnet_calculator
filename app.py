from flask import Flask, request, render_template

def ipv4_address_validator(addr):
    """
    Regex to validate an ipv4 address.
    Checks if each octet is in range 0-255.
    Returns True/False
    """
    import re

    pattern = re.compile(
        r"^([1]?\d?\d|2[0-4]\d|25[0-5])\.([1]?\d?\d|2[0-4]\d|25[0-5])\.([1]?\d?\d|2[0-4]\d|25[0-5])\.([1]?\d?\d|2[0-4]\d|25[0-5])$"
    )
    if pattern.fullmatch(str(addr).strip().strip("\n")):
        return True
    else:
        return False


def cidr_to_common(cidr_mask):
    """Function that returns a common mask (Ex: 255.255.255.0)
       for a given input CIDR mask (Ex: 24)"""
    cidrtocommon = {
        1: "128.0.0.0",
        2: "192.0.0.0",
        3: "224.0.0.0",
        4: "240.0.0.0",
        5: "248.0.0.0",
        6: "252.0.0.0",
        7: "254.0.0.0",
        8: "255.0.0.0",
        9: "255.128.0.0",
        10: "255.192.0.0",
        11: "255.224.0.0",
        12: "255.240.0.0",
        13: "255.248.0.0",
        14: "255.252.0.0",
        15: "255.254.0.0",
        16: "255.255.0.0",
        17: "255.255.128.0",
        18: "255.255.192.0",
        19: "255.255.224.0",
        20: "255.255.240.0",
        21: "255.255.248.0",
        22: "255.255.252.0",
        23: "255.255.254.0",
        24: "255.255.255.0",
        25: "255.255.255.128",
        26: "255.255.255.192",
        27: "255.255.255.224",
        28: "255.255.255.240",
        29: "255.255.255.248",
        30: "255.255.255.252",
        31: "255.255.255.254",
        32: "255.255.255.255",
    }
    if int(cidr_mask) >= 0 and int(cidr_mask) <= 32:
        return cidrtocommon[int(cidr_mask)]
    else:
        raise ValueError("Incorrect CIDR mask entered")


def common_to_cidr(common_mask):
    """Function that returns a CIDR mask (Ex: 24)
        for a given input common mask (Ex: 255.255.255.0)"""
    commontocidr = {
        "128.0.0.0": 1,
        "192.0.0.0": 2,
        "224.0.0.0": 3,
        "240.0.0.0": 4,
        "248.0.0.0": 5,
        "252.0.0.0": 6,
        "254.0.0.0": 7,
        "255.0.0.0": 8,
        "255.128.0.0": 9,
        "255.192.0.0": 10,
        "255.224.0.0": 11,
        "255.240.0.0": 12,
        "255.248.0.0": 13,
        "255.252.0.0": 14,
        "255.254.0.0": 15,
        "255.255.0.0": 16,
        "255.255.128.0": 17,
        "255.255.192.0": 18,
        "255.255.224.0": 19,
        "255.255.240.0": 20,
        "255.255.248.0": 21,
        "255.255.252.0": 22,
        "255.255.254.0": 23,
        "255.255.255.0": 24,
        "255.255.255.128": 25,
        "255.255.255.192": 26,
        "255.255.255.224": 27,
        "255.255.255.240": 28,
        "255.255.255.248": 29,
        "255.255.255.252": 30,
        "255.255.255.254": 31,
        "255.255.255.255": 32,
    }
    return commontocidr[common_mask]

def ipv4_subnet_details(addr, mask):
    """
    Function that prints the subnet related details- Network, Broadcast, Host IP range and number of host addresses
    :param addr: IP address
    :param mask: subnet mask
    :return: result dictionary containing the details
    """
    network_address = []
    broadcast_address = []
    num_ips = 1  # to keep track of total no of ips in this subnet by multiplying (wcmask per octet+1) in the loop
    wildcard_mask = {
        "255": "0",
        "254": "1",
        "252": "3",
        "248": "7",
        "240": "15",
        "224": "31",
        "192": "63",
        "128": "127",
        "0": "255",
    }
    for _octet, _mask in zip(
        addr.split("."), mask.split(".")
    ):  # iterate over octet values and mask values simultaneously
        network_address.append(
            str(int(_octet) & int(_mask))
        )  # bitwise AND of the octet value and the mask--> gives the network ip
        broadcast_address.append(
            str(int(_octet) | int(wildcard_mask[_mask]))
        )  # bitwise OR of octet value and wc_mask--> gives the broadcast address
        num_ips *= int(wildcard_mask[_mask]) + 1  # multiplies num hosts per octet
    host_address_low = network_address[:3] + [
        str(int(network_address[3]) + 1)
    ]  # add 1 to last octet of network address to get the first usable host ip
    host_address_high = broadcast_address[:3] + [
        str(int(broadcast_address[3]) - 1)
    ]  # subtract 1 from the last octet of the broadcast address to get the last usable host ip
    host_ips = num_ips - 2  # subtract 2 that is network and bc address
    result = dict()
    result["nw_addr"] = ".".join(network_address)
    result["bc_addr"] = ".".join(broadcast_address)
    result[
        "host_addr_range"
    ] = f"{'.'.join(host_address_low)} to {'.'.join(host_address_high)}"
    result["usable_ips"] = host_ips
    return result


def subnetting_funct(addr, mask, subnetting_mask):
    """
    Function to print the total no. of subnets possible from the parent network for the given valid subnetting mask
    :param addr: input ip address
    :param mask: mask of the original IP network
    :param subnetting_mask: mask of the subnet
    :return: None
    """
    wildcard_mask = {
        "255": "0",
        "254": "1",
        "252": "3",
        "248": "7",
        "240": "15",
        "224": "31",
        "192": "63",
        "128": "127",
        "0": "255",
    }
    result_to=dict()
    total_sub_networks = 2 ** (
        common_to_cidr(subnetting_mask) - common_to_cidr(mask)
    )
    result_to['Total Subnets']=total_sub_networks
    for i in range(total_sub_networks):
        if i == 0:
            next_addr = ipv4_subnet_details(addr, mask)["nw_addr"]
            result_to["Subnet"+str(i+1)]=str(next_addr)+"/"+str(common_to_cidr(subnetting_mask))
        else:
            next_addr_list = []
            carry = 0
            j = 0
            for _net, _mask in zip(
                next_addr.split(".")[::-1],
                list(map(lambda x: wildcard_mask[x], subnetting_mask.split(".")))[::-1],
            ):  # start from 4th octet, end at 1st octet. This loop is to obtain the next network ip.
                j += 1
                if j == 1:  # 4th octet
                    if (
                        int(_net) + int(_mask) + 1 > 255
                    ):  # add the value in the octet (of IP) with the wc mask octet + 1. If this is > 255, generate a carry for the next octet.
                        carry = 1
                        next_addr_list.append("0")
                    elif int(_net) + int(_mask) + 1 <= 255:
                        next_addr_list.append(str(int(_net) + int(_mask) + 1))
                else:
                    if carry == 1:
                        if int(_net) + int(_mask) + 1 <= 255:
                            next_addr_list.append(str(int(_net) + int(_mask) + 1))
                            carry = 0
                        elif int(_net) + int(_mask) + 1 > 255:
                            next_addr_list.append("0")
                            carry = 1
                    elif carry == 0:
                        next_addr_list.append(
                            _net
                        )  # if there is no carry, keep octet as is.
            next_addr = ".".join(
                next_addr_list[::-1]
            )  # reverse it again to read as octet 1 to octet 4
            result_to["Subnet"+str(i+1)]=str(next_addr)+"/"+str(common_to_cidr(subnetting_mask))
    return result_to

app = Flask(__name__)

@app.route('/', methods=['GET','POST'])
def index():
	if request.method=="POST":
		ipaddr=request.form['ipaddr']
		mask=request.form['mask']
		mask_to=request.form['mask_to']
		if ipv4_address_validator(ipaddr) and (int(mask)>0 and int(mask)<=32) and (int(mask_to)>int(mask) and int(mask_to)<=32):
			return render_template("calc.html", result=ipv4_subnet_details(ipaddr,cidr_to_common(mask)), mask_to=mask_to, mask=mask, subnet_to=subnetting_funct(ipaddr,cidr_to_common(mask),cidr_to_common(mask_to)))
		else:
			return render_template("calc.html", incorrect=True)
	else:
		return render_template("calc.html")
if __name__ == '__main__':
    app.run()
