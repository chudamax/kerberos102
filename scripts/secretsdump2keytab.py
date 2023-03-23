from struct import unpack, pack
import argparse
from impacket.structure import Structure
import binascii
import sys

import re


class KeyTab(Structure):
    structure = (
        ('file_format_version','H=517'),
        ('keytab_entry', ':')
    )
    def fromString(self, data):
        self.entries = []
        Structure.fromString(self, data)
        data = self['keytab_entry']
        while len(data) != 0:
            ktentry = KeyTabEntry(data)

            data = data[len(ktentry.getData()):]
            self.entries.append(ktentry)

    def getData(self):
        self['keytab_entry'] = b''.join([entry.getData() for entry in self.entries])
        data = Structure.getData(self)
        return data

class OctetString(Structure):
    structure = (
        ('len', '>H-value'),
        ('value', ':')
    )

class KeyTabContentRest(Structure):
    structure = (
        ('name_type', '>I=1'),
        ('timestamp', '>I=0'),
        ('vno8', 'B=2'),
        ('keytype', '>H'),
        ('keylen', '>H-key'),
        ('key', ':')
    )

class KeyTabContent(Structure):
    structure = (
        ('num_components', '>h'),
        ('realmlen', '>h-realm'),
        ('realm', ':'),
        ('components', ':'),
        ('restdata',':')
    )
    def fromString(self, data):
        self.components = []
        Structure.fromString(self, data)
        data = self['components']
        for i in range(self['num_components']):
            ktentry = OctetString(data)

            data = data[ktentry['len']+2:]
            self.components.append(ktentry)
        self.restfields = KeyTabContentRest(data)

    def getData(self):
        self['num_components'] = len(self.components)
        # We modify the data field to be able to use the
        # parent class parsing
        self['components'] = b''.join([component.getData() for component in self.components])
        self['restdata'] = self.restfields.getData()
        data = Structure.getData(self)
        return data

class KeyTabEntry(Structure):
    structure = (
        ('size','>I-content'),
        ('content',':', KeyTabContent)
    )

def parser_error(errmsg):
    print("Usage: python3 " + sys.argv[0] + " [Options] use -h for help")
    print ("Ex: python3 keytab.py -i ntds.kerberos -o keytab.keytab -d hpbank.local")
    print("Error: " + errmsg)
    sys.exit()
    
def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython3 ' + sys.argv[0] + " -m")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-i','--file-input', help="file with kerberos keys", required=True)
    parser.add_argument('-o','--file-output', help="output keytab file", required=True)

    return parser.parse_args()

def main():
    args = parse_args()

    domain = 'hpbank.local'
    keys_file_paths = args.file_input.split(',')
    output_keytab_path = args.file_output

    nkt = KeyTab()
    nkt.entries = []


    for keys_file_path in keys_file_paths:
        all_txt = open(keys_file_path).read()

        regex = r"(.*)\\\w"
        matches = re.findall(regex, all_txt)
        domain = matches[0]

        keys = [key.strip() for key in all_txt.split('\n')]
        for keystr in keys:
            username = keystr.split(':')[0]
            
            if '\\' in username:
                domain = username.split('\\')[0]
                username = username.split('\\')[1]
                
            keytype_str = keystr.split(':')[1]
            key = keystr.split(':')[2]
                
            if 'aes256-cts-hmac-sha1-96' in keytype_str:
                keytype = 18
            elif 'aes128-cts-hmac-sha1-96' in keytype_str:
                keytype = 17
            elif 'des-cbc-md5' in keytype_str:
                keytype = 3
            elif 'rc4' in keytype_str:
                keytype = 23
            else:
                continue
            
            item = {'name':username, 'domain':domain, 'key':key, 'keytype':keytype}
            print (item)

            ktcr = KeyTabContentRest()
            ktcr['keytype'] = item['keytype']
            ktcr['key'] = binascii.unhexlify(item['key'])
            nktcontent = KeyTabContent()
            nktcontent.restfields = ktcr
            # The realm here doesn't matter for wireshark but does of course for a real keytab
            nktcontent['realm'] = item['domain'].upper()
            
            user = OctetString()
            user['value'] = item['name']
            nktcontent.components = [user]
            nktentry = KeyTabEntry()
            nktentry['content'] = nktcontent
            nkt.entries.append(nktentry)

    data = nkt.getData()
    if len(sys.argv) < 3:
        print('Usage: keytab.py <outputfile>')
        print('Keys should be written to the source manually')
    else:
        with open(output_keytab_path, 'wb') as outfile:
            outfile.write(data)

if __name__ == '__main__':
    main()