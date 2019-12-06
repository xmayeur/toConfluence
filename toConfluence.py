#!/usr/bin/env python
# coding: utf-8

import argparse
import json
import os
import re
import sys
from getpass import getpass, getuser
from os import listdir, getcwd
from os.path import isfile, join

import certifi
import requests
from configobj import ConfigObj

# try:
#     from RSAcipher import RSAcipher
# except:
#     RSAcipher = None

RSAcipher = None
SSLVerif = False

if SSLVerif:
    cacerts = certifi.where()
else:
    cacerts = False
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

title = ""
# target = 'Confluence'
target = ""
user = None
pwd = None


def printResponse(r):
    print('{} {}\n'.format(json.dumps(r.json(), sort_keys=True, indent=4, separators=(',', ': ')), r))


def setConfluencePage(docPath=None, fileName='', pageId=None, spaceKey=None, parentPageId=None, mdConvert=False):
    # dummy get to log into
    r = requests.get(url, auth=(user, pwd), verify=cacerts)
    if r.status_code != 200:
        return r.status_code

    title = fileName.replace(" ", "%20")
    utitle = title.split('.')[0]
    docName = fileName
    imgName = fileName.split('.')[0] + ".png"

    if pageID is None:
        # Search for a confluence page by title

        pageId = None

        # http://localhost:8080/confluence/rest/api/content?title=myPage%20Title&spaceKey=TST&expand=history"
        reqUrl = url + "?title=" + utitle + "&spaceKey=" + spaceKey + "&expand=history"
        r = requests.get(reqUrl, auth=(user, pwd), verify=cacerts)

        if r.status_code == 200:
            print(r)
            pageData = (r.json())
            results = pageData['results']
            if len(results) == 0:
                print('page not found')
            else:
                pageId = results[0]['id']
                print('Page ID: ' + pageId)
        else:
            printResponse(r)

    # open the existing Confluence page
    if pageId is not None:
        reqUrl = url + pageId  # +"?expand=body.storage"
        r = requests.get(reqUrl, auth=(user, pwd), verify=cacerts)

        # print(r.text)
        if r.status_code == 200:
            pageData = (r.json())
            # myBody = pageData['body']['storage']['value']
            key = pageData["space"]["key"]
            title = pageData["title"]
            print("Page title: " + title)
            parentPage = r.json()
        else:
            printResponse(r)

    # or create o new page  under the parent page
    else:
        newPageData = {
            'type': 'page',
            'title': title,
            "ancestors": [{"id": parentPageId}],
            'space': {'key': spaceKey},
            'body': {'storage': {'value': "_Empty_", 'representation': 'wiki'}}
        }
        r = requests.post(url,
                          data=json.dumps(newPageData),
                          auth=(user, pwd),
                          headers=({'Content-Type': 'application/json'}),
                          verify=cacerts)

        if r.status_code == 200:
            # Retrieve the new Page ID
            reqUrl = url + "?title=" + utitle + "&spaceKey=" + spaceKey + "&expand=history"
            r = requests.get(reqUrl, auth=(user, pwd), verify=cacerts)

            if r.status_code == 200:
                pageData = (r.json())
                results = pageData['results']
                if len(results) == 0:
                    print('page not found')
                else:
                    pageId = results[0]['id']
                    print('New Page ID: ' + pageId)
            else:
                printResponse(r)

    # upload or update the main image associated to the page
    # check list of existing attachments
    # get attachments from the target Confluence page

    attId = ''

    reqUrl = url + pageId + "/child/attachment"
    r = requests.get(reqUrl, auth=(user, pwd), verify=cacerts)
    existAtt = r.json()['results']
    for a in existAtt:
        print(a['title'] + ": " + a['id'])
        if imgName == a['title']:
            attId = a['id']

            print('File ' + imgName + ' already exist... updating...')
            files = {'file': open(docPath + imgName, 'rb'), 'minorEdit': 'false', 'comment': 'Updated image '}
            r = requests.post(url + pageId + "/child/attachment/" + attId + '/data',
                              auth=(user, pwd),
                              headers=({'X-Atlassian-Token': 'no-check'}),
                              verify=cacerts,
                              files=files)
            break
    else:
        print('Uploading a new attachment...')
        files = {'file': open(docPath + imgName, 'rb')}
        r = requests.post(url + pageId + "/child/attachment",
                          auth=(user, pwd),
                          headers=({'X-Atlassian-Token': 'no-check'}),
                          verify=cacerts,
                          files=files)

    if r.status_code != 200:
        printResponse(r)

    # Open the Confluence wiki formatted document and load its content
    with open(docPath + '\\' + docName, 'r') as f:
        docContent = f.read()

    if ".md" in docName or mdConvert:
        docContent = md_to_wiki(docContent)

    # scan docContent for attachments and upload attachment if file is found in the 'files' folder
    _path = docPath.split('\\')
    filesPath = docPath[:-len(_path[len(_path) - 2]) - 2] + '\\files\\'

    pat = r'\|\^(.*?)\]'
    r = re.compile(pat)
    for m in r.finditer(docContent):
        attName = m.group(1)
        for a in existAtt:
            print(a['title'] + ": " + a['id'])
            if attName == a['title']:
                attId = a['id']
                print('File ' + attName + ' already exist... updating...')

                files = {'file': open(filesPath + attName, 'rb'), 'minorEdit': 'false', 'comment': 'Updated image '}
                r = requests.post(url + pageId + "/child/attachment/" + attId + '/data',
                                  auth=(user, pwd),
                                  headers=({'X-Atlassian-Token': 'no-check'}),
                                  verify=cacerts,
                                  files=files)
                break
        else:
            print('Uploading a new attachment ' + attName)
            files = {'file': open(filesPath + attName, 'rb')}
            r = requests.post(url + pageId + "/child/attachment",
                              auth=(user, pwd),
                              headers=({'X-Atlassian-Token': 'no-check'}),
                              verify=cacerts,
                              files=files)

        if r.status_code != 200:
            printResponse(r)

    # Upload now the page body

    # get the version number of the page to update
    if pageId is not None:
        r = requests.get(url + pageId + "?expand=version", auth=(user, pwd), verify=cacerts)

        if r.status_code == 200:
            pageData1 = (r.json())
            version = int(pageData1['version']['number']) + 1
            print("Document next version is: " + str(version))
        else:
            printResponse(r)
            version = 1

        # Replace and update the content of an existing page using XHTML storage format
        # Example 
        # curl -u admin:admin -X PUT -H 'Content-Type: application/json' -d '{"id":"3604482","type":"page",
        # "title":"new page","space":{"key":"TST"},"body":{"storage":{"value":
        # "<p>This is the updated text for the new page</p>","representation":"storage"}},
        # "version":{"number":2}}' http://localhost:8080/confluence/rest/api/content/3604482 | python -mjson.tool

        newPageData = {
            'type': 'page',
            'id': pageId,
            'title': title,
            'space': {'key': spaceKey},
            'version': {'number': version},
            'body': {'storage': {'value': docContent, 'representation': 'wiki'}}
        }

        r = requests.put(url + pageId,
                         data=json.dumps(newPageData),
                         auth=(user, pwd),
                         headers=({'Content-Type': 'application/json'}),
                         verify=cacerts)

        if r.status_code == 200:
            print("Page updated!")
        else:
            printResponse(r)

    return r.status_code


def main():
    # Parse command line arguments
    global pageID, parentPageID, target, url, spaceKey, user, pwd

    parser = argparse.ArgumentParser("create or update Confluence page using wiki markdown files")

    parser.add_argument("-d", "--directory",
                        help="handle all .wi files in the specified directory")
    parser.add_argument("-id", "--pageid", required=False,
                        help="update using page ID instead of file name")
    parser.add_argument("-pid", "--parentid", required=False,
                        help="specify the parent page ID")
    parser.add_argument("-o", "--OrangeSharing", required=False, action='store_true',
                        help="specify the OrangeSharing as Confluence site")
    parser.add_argument('-k', '--spacekey', default='EAO',
                        help="specify the Confluence Space key - default is 'EAO'")
    parser.add_argument('-m', '--markdown', required=False, action='store_true',
                        help="force to convert file from markdown to Confluence wiki")
    parser.add_argument('file', nargs='?',
                        help="handle the specified file")
    args = parser.parse_args()

    # Set default values from config file

    if os.name == 'nt':
        config_file = 'H:/toConfluence.conf'
    else:
        config_file = '~/toConfluence.conf'

    try:
        config = ConfigObj(config_file)
    except IOError:
        print('Warning: Config file does not exit')
        config = ConfigObj()
        config.filename = config_file
        config['token'] = ''
        config.write()

    try:
        url = config['url']
        spaceKey = config['spaceKey']
    except KeyError:
        url = 'https://confluence.europe.intranet/rest/api/content/'
        spaceKey = args.spacekey

    # get user's credentials
    user = getuser()
    pwd = os.getenv('PWD')
    # set path to crypto key to decrypt the saved password
    if os.name == 'nt':
        rsaKey = 'c:/users/' + user + '/' + user
    else:
        rsaKey = '~/.' + user

    if RSAcipher is not None:
        # create a key if needed
        if not os.path.exists(rsaKey + '.key'):
            rsa = RSAcipher()
            rsa.create_keyset(rsaKey)

        try:
            # get & decrypt the password
            token = config['token']
            rsa = RSAcipher(certfile=rsaKey + '.key')
            pwd = rsa.decrypt(token)
        except:
            pwd = None
            token = ''
            config['token'] = token
            config.write()

    if pwd is None:
        pwd = getpass('Enter password for user ' + user + ": ")
        if RSAcipher is not None:
            rsa = RSAcipher(certfile=rsaKey + '.pub')
            token = rsa.encrypt(pwd)
            config['token'] = token
            config.write()

    pageID = None
    if args.pageid:
        pageID = args.pageid
    else:
        try:
            pageID = config['pageid']
        except KeyError:
            pageID = None

    if args.parentid:
        parentPageID = args.parentid
    else:
        try:
            parentPageID = config['parentid']
        except KeyError:
            parentPageID = None

    if args.directory:
        docPath = args.directory
        if docPath == '.':
            docPath = os.getcwd()
        files = [f for f in listdir(docPath) if isfile(join(docPath, f))]
        for f in files:
            # something to do here for md files
            if ".wi" in f:
                print('file: ' + f)
                # title = f.replace('.wi', '')
                code = setConfluencePage(docPath, f, pageID, spaceKey, parentPageID, args.markdown)
                if code == 401:
                    print("Authorization failure!")
                    token = ''
                    config['token'] = ''
                    config.write()
                    sys.exit(1)
        sys.exit(0)

    if args.file:
        filePath = args.file
        fileRelative = filePath.split("\\")

        if len(fileRelative) == 1:
            docPath = getcwd() + '\\'
        else:
            docPath = filePath[0:len(filePath) - len(fileRelative[len(fileRelative) - 1])]

        f = fileRelative[len(fileRelative) - 1]
        ext = fileRelative[len(fileRelative) - 1].split('.')[1]
        if ext == 'md':
            args.markdown = True
        print('docPath: ' + docPath + '\ntitle: ' + title)
        code = setConfluencePage(docPath, f, pageID, spaceKey, parentPageID, args.markdown)
        if code == 401:
            print("Authorization failure!")
            token = ''
            config['token'] = ''
            config.write()
            sys.exit(1)
        sys.exit(0)

def escapeRegExp(str):
    s= re.sub(r'([-\/\\^$*+?.()|[\]{}])', r'\\\1', str, 0)
    return s


def md_to_wiki(doc):
    s = doc

    # replace curly braces to avoid entering Confluence macros
    s = re.sub(r'\{(.*)\}', r"\\{\1\\}", s, 0, re.M)

    # replace headers
    s = re.sub(r'^#####', 'h5. ', s, 0, re.M)
    s = re.sub(r'^####', 'h4. ', s, 0, re.M)
    s = re.sub(r'^###\s*(.*)\s*$', r'h3. {color:blue}\1{color}', s, 0, re.M)
    s = re.sub(r'^##\s*(.*)\s*$', r'h2. {color:blue}*\1*{color}', s, 0, re.M)
    s = re.sub(r'^#\s*(.*)\s*$', r'h1. {color:blue}*\1*{color}', s, 0, re.M)

    # replace italic
    s = re.sub(r'\*(.*)\*', r'_\1_', s, 0)

    # replace bold
    s = re.sub(r'_\*(.*)\*_', r'*\1*', s, 0)

    # replace numbered list
    s = re.sub(r'^[0-9]\.\s+', r'# ', s, 0, re.M)
    s = re.sub(r'^\s+[0-9]\.\s+', r'## ', s, 0, re.M)

    # replace unordered list
    s = re.sub(r'^\*\s+', r'* ', s, 0, re.M)
    s = re.sub(r'^\t\*\s+', r'** ', s, 0, re.M)
    s = re.sub(r'^\s{4}\*\s+', r'** ', s, 0, re.M)

    # replace tables
    pat = r'(\|.*?)\|\s*\n\|\s*-+\s*\|.*\n'
    for m in re.finditer(pat, s):
        hdr = m[1]
        header = re.sub(r'\|', '||', m[1], 0) + '||\n'
        s = re.sub(escapeRegExp(hdr) + r'\|\s*\n\|\s*-+\s*\|.*\n', header, s, 1)

    # images
    pat = r'!\[.*\]\((.*)\s*.*\)'
    s = re.sub(pat, r'!\1|width=1000px!', s, 0, re.M)

    pat = r'\!.*?\|width'
    m = re.search(pat, s)
    # Find all rule matches.
    matches = [(match.start(), match.end(), match.group(0)) for \
               match in re.finditer(pat, s)]
    # Start from behind, so replace in-place.
    matches.reverse()
    # Convert to characters because strings are immutable.
    characters = list(s)
    for start, end, txt in matches:
        characters[start:end] = txt.replace('%20', ' ')
    # Convert back to string.
    s = "".join(characters)

    # links
    s = re.sub(r'(.*)\[(.*)\]\((.*)\)', r'\1[\2|\3]', s, 0, re.M)

    # manage file://... as attachments
    # the group between [ and | contains the file name without path
    pat = r'\[(.*)\|\s*file\:.*\/(.*?)\s*\]'
    s = re.sub(pat, r'File: [\1|^\2]', s, 0, re.M)

    pat = r'\[.*?\|\^.*?\]'
    # Find all %20 matches in attachment name.
    matches = [(match.start(), match.end(), match.group(0)) for \
               match in re.finditer(pat, s)]
    # Start from behind, so replace in-place.
    matches.reverse()
    # Convert to characters because strings are immutable.
    characters = list(s)
    for start, end, txt in matches:
        characters[start:end] = txt.replace('%20', ' ')
    # Convert back to string.
    s = "".join(characters)

    # find code block
    # preceded by a file attachment corresponding to the code
    # pat = r'\[(.*)\.(.*)\^.*\]\n*```'
    pat = r'\[(.*?)\|\^(.*?)\.(.*?)\]\n*```'
    rep = r'[\1|^\2.\3]\n\n{code:title=\1|linenumbers=true|language=text|firstline=0001|collapse=true}\n{code}'
    s = re.sub(pat, rep, s, 0, re.M | re.VERBOSE)
    pat = r'\{code\}(.*?)```'
    # cb = re.search(pat, s, re.M|re.DOTALL).group(1)
    rep = r'\1\n{code}'
    s = re.sub(pat, rep, s, 0, re.M | re.DOTALL)

    # or just a simple code block
    pat = r'```(.*?)```'
    rep = r'{code:title=code|linenumbers=true|firstline=0001|collapse=true}\n\1\n{code}'
    s = re.sub(pat, rep, s, 0, re.M | re.DOTALL)

    # find relationships paragraph with table and put it in an expand block
    pat = r'\*+(Relationships.*?)\*+\n*---\n(\|\|.*?\|)\n+---'
    rep = r'{expand:\1}\n\2\n{expand}\n'
    s = re.sub(pat, rep, s, 0, re.M | re.DOTALL)

    return s


if __name__ == "__main__":
    main()
