import os, sys
import getopt
from collections import defaultdict
from collections import OrderedDict
import csv
import re
import pprint

pp = pprint.PrettyPrinter(indent=4)

def left_outer_join(left, right, join_key, attr_keys):
    """
    Allows the joining of the "left" dictionary to "right" dictionary as defined by the "join_key", much
    the same as SQL 'Left Outer Join' would
     
    Params::
    
    - left - list of objects to join to
    - right - list of dictionaries from which to get joined data
    - join_key - attribute of both object and dictionary with which we can match
    - attr_keys - the list of keys on the right dict you want to join
    
    """

    # convert our list of dicts to a dict of dicts
    right = dict((r.get(join_key), r) for r in right)
 
    # attach the inner dict values to the attr on the object
    for l in left:
        right_vals = right.get(l[join_key], {})
        # attach attributes to our objects
        for key in attr_keys:
            l[key] = right_vals.get(key)

    return left

def maked(obj):
    ''' makes a nice clean dict from our csv.DictReader obj '''
    ds = []
    for row in obj:
        ds.append( clean_keys(row) )
    return ds

def makepatchlinksd(obj):
    ''' makes a special Dict for patchlinks to account for multiple links for one QID '''    
    pld = maked(obj)

    dd = defaultdict(list)
    for row in pld:
        dd[row['QID']].append(row['Link'])

    o = []
    for qid, link in dd.iteritems():
        d = {}
        d['QID'] = qid
        d['Link'] = ', '.join(link)

        o.append(d)

    return o

def clean_keys(item):
    '''
        Strips whitespace out of keys
        and normalized QID field names, i.e "Patch QID" becomes 'qid'
    '''
    retd = {}
    for k,v in item.iteritems():
        if k == 'Patch QID':
            k = 'QID'
        key = k.strip()
        retd[key] = v
    return retd

def readinputs(argv):
    '''
     reads the inputs from sys.argv and puts them in a dict for processing.
    '''
    try:
        optlist, args = getopt.getopt(argv, '', ['input=', 'output='])
    except getopt.GetoptError, e:
        usage(e)
        sys.exit(2)

    if len(optlist) < 2:
        usage()
        sys.exit(2)
    
    returnDict = {}
    for name, value in optlist:
       returnDict[name[2:]] = value.strip()

    return returnDict

def usage(error=False):
    print "\n"
    if error:
        print "ERROR: There was an error: %s" % ( error )

    print "Usage:"
    print "%s --input=<patch_report> --output=<output_file>" % (__file__)
    print "example: %s --input=some_patch_report.csv --output=converted_patch_report.csv" % ( __file__)
    print "\n"

def main(argv):

    opts = readinputs(argv)

    inputfile = opts['input']
    outputfile = opts['output']

    with open(inputfile, 'rU') as f:

        file_data = f.read()

        ''' Extract Patch List '''
        patchlist = re.search(r"^Patch List,,,,,,,,$(.*?)^Patches by Host[,]+", file_data, re.DOTALL|re.MULTILINE)
        patchlist = patchlist.group(1).lstrip()
        patchlistcsv = csv.DictReader(patchlist.splitlines())
        patchlistd = maked(patchlistcsv)

        ''' Extract Patches by Host '''
        patches_by_host = re.search(r'^Patches by Host,,,,,,,,$(.*?)^Host Vulnerabilities Fixed by Patch,,,,,,,,', file_data, re.DOTALL|re.MULTILINE)
        patches_by_host = patches_by_host.group(1).lstrip()
        patchesbyhostcsv = csv.DictReader(patches_by_host.splitlines())
        patchesbyhostd = maked(patchesbyhostcsv)

        ''' Extract Host Vulns Fixed by Patch '''
        host_vulns = re.search(r'^Host Vulnerabilities Fixed by Patch,,,,,,,,(.*?)^Patch Links\.,,,,,,,,', file_data, re.DOTALL|re.MULTILINE)
        host_vulns = host_vulns.group(1).lstrip()
        hostvulnscsv = csv.DictReader(host_vulns.splitlines())
        hostvulnsd = maked(hostvulnscsv)

        ''' Extract Patch Links '''
        patch_links = re.search(r'^Patch Links\.,,,,,,,,$(.*)', file_data, re.DOTALL|re.MULTILINE)
        patch_links = patch_links.group(1).lstrip()
        patchlinkscsv = csv.DictReader(patch_links.splitlines())
        #patchlinksd = maked(patchlinkscsv)
        patchlinksd = makepatchlinksd(patchlinkscsv)




    ''' join the "patches by host" to the "patch links" section by qid '''
    mapped = left_outer_join( patchesbyhostd, patchlinksd, 'QID', ['OS/SW', 'Link'] )

    ''' join our newly mapped dict to the "patch list" section to get the vuln details '''
    mapped = left_outer_join( mapped, patchlistd, 'QID', ['Vendor ID', 'Severity', 'Title', 'Published'])
    
    ''' output our now mapped sections to csv '''
    with open(outputfile, 'wb') as o:

        ''' field names for the csv, can also change order to move columns around if needed '''
        fnames = ['IP', 'DNS', 'NetBIOS', 'OS', 'OS CPE', 'QID', 'Title', 'Severity', 'Published', 'Vendor ID', 'Link', 'OS/SW', 'Vulnerability Count', '']

        w = csv.DictWriter(o, fieldnames=fnames)
        w.writeheader()

        for row in mapped:
            w.writerow(row)

    print '\n SUCCESS! File "%s" has been mapped and outputted to "%s"\n' % ( inputfile, outputfile )
    print 'All done. No Errors'

if __name__ == "__main__":
    main(sys.argv[1:])
   
