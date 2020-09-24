#!/usr/bin/env python
# coding: utf-8

########################################################################################################
#                                                                                                      #
#   This program read and upload files and attachments to Confluence                                   #
#   File format can be either native Confluence wiki format or MarkDown format                         #
#                                                                                                      #
#   Author: Xavier Mayeur                                                                              #
#   Version 2.0:                                                                                       #
#     - replace requests library with pycurl to manage firewall authentication                         #
#                                                                                                      #
#                                                                                                      #
########################################################################################################

# --> TO DO <---
# replace print(...) by log(...) function

import argparse
import hashlib
import json
import os
import re
import sys
from getpass import getpass, getuser
from os import listdir, getcwd
from os.path import isfile, join

import certifi
import urllib3
import win32clipboard
from configobj import ConfigObj

from curlx import CurlX, Response

version = '2.01'

#
#   When including the RSACipher module, user password may be encrypted and stored in the config file
#   As this is not ING compliant, the module has been removed, but the logic remains in the code
#
# try:
#     from RSAcipher import RSAcipher
# except:
#     RSAcipher = None

RSAcipher = None
SSLVerif = False

#  ---> TO BE TESTED <----
if SSLVerif:
    cacerts = certifi.where()
else:
    cacerts = False
    from urllib3.exceptions import InsecureRequestWarning

    urllib3.disable_warnings(InsecureRequestWarning)

user = None
pwd = None
email = None
debug = False
cookies = None
PROXY_URL = None
auth = None


def file_md5(f):
    hasher = hashlib.md5()
    with open(f, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    return str(hasher.hexdigest())


class Clip:

    def __init__(self):
        win32clipboard.OpenClipboard()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        win32clipboard.CloseClipboard()

    def empty(self):
        win32clipboard.EmptyClipboard()

    def copy(self, s):
        win32clipboard.SetClipboardData(s)

    def paste(self):
        return win32clipboard.GetClipboardData()


def setConfluencePage(docPath=None, fileName='', url=None, pageId=None, spaceKey=None, parentPageId=None,
                      mdConvert=False):
    '''

    This function uploads the document defined by the fileName argument in the docPath folder
    to Confluence url, specifying specific destination parameters

    The function also upload all .images and file attachments that are in the ../.images and ../files folders of the
    docPath folder and that are referred as links in the content of the fileName document

    Confluence page and attachments are created if not existing or replaced (with version control if exist

    @param docPath: string  - the directory path of the document to upload to COnfluence
    @param fileName: string - the name of the document to be uploaded
    @param pageId: string   - the Confluence page ID as target - if empty, the document name without extension is used
    @param spaceKey: string - the Confluence space short name
    @param parentPageId: string - the Confluence parent page ID under which the uploaded page will be created
    @param mdConvert: boolean   - flag to force the conversion from markdown to wiki format
    @return: string         - the response status from the last http request

    '''
    r = Response

    # verify username and password are valid or _exit
    # dummy get to log into
    requests = CurlX(proxy=proxy, auth=auth, verify=cacerts, cookies=cookies)
    r = requests.get(url)
    if r.status_code != 200:
        requests.close()
        return r.status_code

    # filename without extension
    utitle = fileName.split('.')[0]
    title = fileName.replace(" ", "%20")
    docName = fileName
    imgName = utitle + ".png"

    if pageId is None:
        # Search for a confluence page by title
        # http://localhost:8080/confluence/rest/api/content?title=myPage%20Title&spaceKey=TST&expand=history"
        reqUrl = url + "?title=" + utitle.replace(" ", "%20") + "&spaceKey=" + spaceKey + "&expand=history"
        r = requests.get(reqUrl)

        if r.status_code == 200:
            pageData = json.loads(r.body)
            results = pageData['results']
            if len(results) == 0:
                print('page not found')
            else:
                pageId = results[0]['id']
                print('Page ID: ' + pageId)
        elif debug:
            print(r.status_code)

    # if found, open the existing Confluence page
    if pageId is not None:
        reqUrl = url + pageId  # +"?expand=body.storage"
        r = requests.get(reqUrl)

        if r.status_code == 200:
            pageData = json.loads(r.body)
            # myBody = pageData['body']['storage']['value']
            key = pageData["space"]["key"]
            title = pageData["title"]
            print("Page title: " + title)
        elif debug:
            print('Error opening page with ID ' + str(pageId))
            print(r.status_code)

    # or create o new page  under the parent page
    else:
        newPageData = {
            'type': 'page',
            'title': utitle,
            "ancestors": [{"id": parentPageId}],
            'space': {'key': spaceKey},
            'body': {'storage': {'value': "_Empty_", 'representation': 'wiki'}}
        }
        r = requests.post(url, data=json.dumps(newPageData))

        if r.status_code == 200:
            # Retrieve the new Page ID
            reqUrl = url + "?title=" + utitle + "&spaceKey=" + spaceKey + "&expand=history"
            r = requests.get(reqUrl)
            if r.status_code == 200:
                pageData = json.loads(r.body)
                results = pageData[0]['results']
                if len(results) == 0:
                    print('page not found')
                else:
                    pageId = results[0]['id']
                    print('New Page ID: ' + pageId)
            else:
                if debug:
                    print('Cannot retrieve new page ID - http error ' + str(r.status_code))
                    print(r.body)
        else:
            requests.close()
            return r.status_code

    # upload or update the main image associated to the page
    # check list of existing attachments
    # get attachments from the target Confluence page

    reqUrl = url + str(pageId) + "/child/attachment"
    r = requests.get(reqUrl)
    if r.status_code == 200:
        pageData = json.loads(r.body)
    else:
        print(r.status_code)
        requests.close()
        return r.status_code

    existAtt = pageData['results']
    for a in existAtt:
        # print(a['title'] + ": " + a['id'])
        if imgName == a['title']:
            attId = a['id']
            try:
                comment = a['metadata']['comment']
            except:
                comment = ''

            if os.path.exists(docPath + imgName):
                md5 = file_md5(docPath + imgName)
                if comment != md5:
                    print('File ' + imgName + ' already exist... updating...')
                    files = {'file': docPath + imgName, 'minorEdit': 'false', 'comment': md5}
                    r = requests.post(url + pageId + "/child/attachment/" + attId + '/data',
                                      headers=({'X-Atlassian-Token': 'no-check'}),
                                      files=files)
                    if r.status_code != 200:
                        print('Cannot update existing main image - error ' + str(r.status_code))
            elif debug:
                print('missing main image file')
            break
    else:
        # There is not existing attachment corresponding to the file

        if os.path.exists(docPath + imgName):
            md5 = file_md5(docPath + imgName)
            print('Uploading a new file attachment...')
            files = {'file': docPath + imgName, 'comment': md5}
            r = requests.post(url + pageId + "/child/attachment",
                              headers=({'X-Atlassian-Token': 'no-check'}),
                              files=files)
            if r.status_code != 200:
                print('Cannot create main image - error ' + str(r.status_code))
        # else:
        # print('missing image file')

    # Open the wiki or markdown document and load its content
    with open(docPath + '\\' + docName, 'r', encoding="utf8") as f:
        docContent = f.read()
    doc_md5 = file_md5(docPath + '\\' + docName)
    # if the document is in Markdown format, convert it to Confluence wiki
    if ".md" in docName or mdConvert:
        docContent = md_to_wiki(docContent)

    # scan docContent for file links and upload attachment if a corresponding file is found in the 'files' folder
    # set the files folder path
    _path = docPath.split('\\')
    filesPath = docPath[:-len(_path[len(_path) - 2]) - 1] + '\\files\\'
    if not os.path.isdir(filesPath):
        filesPath = docPath[:-len(_path[len(_path) - 1]) - 1] + '\\.files\\'
        if not os.path.isdir(filesPath):
            if debug:
                print('Error: File path ' + filesPath + ' does not exist!')
    # use regexp to find attachment links patterns
    pat = r'\|\^(.*?)\]'
    reg = re.compile(pat)
    # and search whether the referred file in the links has already a corresponding attachment in Confluence
    for m in reg.finditer(docContent):
        attName = m.group(1)
        for a in existAtt:
            # print(a['title'] + ": " + a['id'])
            if attName == a['title']:
                attId = a['id']
                try:
                    comment = a['metadata']['comment']
                except:
                    comment = ''

                # update the attachment
                if os.path.exists(filesPath + attName):
                    md5 = file_md5(filesPath + attName)
                    if md5 != comment:
                        print('File ' + attName + ' already exist... updating...')
                        files = {'file': filesPath + attName, 'minorEdit': 'false', 'comment': md5}
                        r = requests.post(url + pageId + "/child/attachment/" + attId + '/data',
                                          headers=({'X-Atlassian-Token': 'no-check'}),
                                          files=files)
                        if r.status_code != 200:
                            print('Cannot update file attachment - error ' + str(r.status_code))
                else:
                    print('cannot open file')
                break
        else:
            # If the file does not correspond to an attachment, create one new
            print('Uploading a new file attachment ' + attName)
            if os.path.exists(filesPath + attName):
                md5 = file_md5(filesPath + attName)
                files = {'file': filesPath + attName, 'minorEdit': 'true', 'comment': md5}
                r = requests.post(url + pageId + "/child/attachment",
                                  headers=({'X-Atlassian-Token': 'no-check'}),
                                  files=files)
                if r.status_code != 200:
                    print('Cannot create file attachment - error ' + str(r.status_code))
            else:
                print('cannot open file')

    # scan now docContent for .images and upload attachment if file is found in the '.images' folder
    # this follows the same logic as above for file attachment
    # folder path and link format differ
    filesPath = docPath[:-len(_path[len(_path) - 2]) - 1] + '\\images\\'
    if not os.path.isdir(filesPath):
        filesPath = docPath[:-len(_path[len(_path) - 1]) - 1] + '\\.images\\'
        if not os.path.isdir(filesPath):
            print('Error: File path ' + filesPath + ' does not exist!')
    pat = r'\!([^|]*?)\!'
    reg = re.compile(pat)
    for m in reg.finditer(docContent):
        attName = m.group(1)
        for a in existAtt:
            # print(a['title'] + ": " + a['id'])
            if attName == a['title']:
                attId = a['id']
                try:
                    comment = a['metadata']['comment']
                except:
                    comment = ''

                if os.path.exists(filesPath + attName):
                    md5 = str(file_md5(filesPath + attName))
                    if md5 != comment:
                        print('File ' + attName + ' already exist... updating...')
                        files = {'file': filesPath + attName, 'minorEdit': 'true', 'comment': md5}
                        r = requests.post(url + pageId + "/child/attachment/" + attId + '/data',
                                          headers=(['Accept-Language: en', 'X-Atlassian-Token: nocheck']),
                                          files=files)
                        if r.status_code != 200:
                            print('error uploading image ' + attId + ' update ' + str(r.status_code))
                            print(r.body)
                else:
                    print('Cannot open file')
                break
        else:
            print('Uploading a new  image attachment ' + attName)
            if os.path.exists(filesPath + attName):
                md5 = file_md5(filesPath + attName)
                files = {'file': filesPath + attName, 'comment': md5}
                r = requests.post(url + pageId + "/child/attachment",
                                  headers=(['Accept-Language: en', 'X-Atlassian-Token: no-check']),
                                  files=files)
                if r.status_code != 200:
                    print('error create image update ' + str(r.status_code))
            else:
                print('Cannot open file')

    # Upload now the page body
    # get the version number of the page to update, if it exist
    if pageId is not None:
        r = requests.get(url + pageId + "?expand=version")

        if r.status_code == 200:
            pageData1 = json.loads(r.body)
            doc_version = int(pageData1['version']['number']) + 1
            try:
                message = pageData1['version']['message']
            except:
                message = ''
        else:
            if debug:
                print('Cannot get current page version + error ' + str(r.status_code))
            doc_version = 2
            message = ''
        print("Document next version is: " + str(doc_version))

        # Replace and update the content of an existing page using XHTML storage format
        # Example
        # curl -u admin:admin -X PUT -H 'Content-Type: application/json' -d '{"id":"3604482","type":"page",
        # "title":"new page","space":{"key":"TST"},"body":{"storage":{"value":
        # "<p>This is the updated text for the new page</p>","representation":"storage"}},
        # "version":{"number":2}}' http://localhost:8080/confluence/rest/api/content/3604482 | python -mjson.tool
        if message != doc_md5:
            newPageData = {
                'type': 'page',
                'id': pageId,
                'title': utitle,
                'space': {'key': spaceKey},
                'version': {'number': doc_version, 'message': doc_md5, 'minorEdit': 'true'},
                'body': {'storage': {'value': docContent, 'representation': 'wiki'}}
            }

            r = requests.put(url + pageId,
                             data=json.dumps(newPageData),
                             headers=({'Content-Type': 'application/json'}),
                             )

            if r.status_code == 200:
                print("Page updated!")
            else:
                print('Cannot update page with id: ' + str(pageId) + ' error - ' + str(r.status_code))
        else:
            print('Document not updated - no update needed')
    requests.close()
    return r.status_code


def main():
    # Parse command line arguments
    global pageID, parentPageID, url, spaceKey, user, pwd, debug, cookies, proxy, email, auth

    parser = argparse.ArgumentParser("create or update Confluence page using wiki or markdown files")

    parser.add_argument("-d", "--directory",
                        help="handle all .wi or .md files in the specified directory")
    parser.add_argument("-id", "--pageid", required=False,
                        help="update using page ID instead of file name")
    parser.add_argument("-pid", "--parentid", required=False,
                        help="specify the parent page ID")
    parser.add_argument("-o", "--OrangeSharing", required=False, action='store_true',
                        help="specify the OrangeSharing as Confluence site and pass the JSESSIONID")
    parser.add_argument('-k', '--spaceKey', default='EAO',
                        help="specify the Confluence Space key - default is 'EAO'")
    parser.add_argument('-m', '--markdown', required=False, action='store_true',
                        help="force to convert file from markdown to Confluence wiki")
    parser.add_argument('-t', '--test', required=False, action='store_true',
                        help="test mode - print out debug information")
    parser.add_argument('-v', '--version', required=False, action='store_true',
                        help="display the application version")
    parser.add_argument('file', nargs='?',
                        help="handle the specified file")
    args = parser.parse_args()

    # Set default values from config file
    print("toConfluence version v" + version)
    if os.name == 'nt':
        config_file = 'toConfluence.conf'
        if not os.path.exists(config_file):
            config_file = os.path.join(os.getenv('USERPROFILE'), 'toConfluence.conf')

    else:
        config_file = '~/toConfluence.conf'

    try:
        config = ConfigObj(config_file)
    except IOError:
        print('Warning: Config file does not _exit')
        config = ConfigObj()
        config.filename = config_file
        config['token'] = ''
        config.write()

    if args.version:
        print('toConfluence version ' + version)
        _exit(0)

    if args.test:
        debug = True

    if args.spaceKey:
        spaceKey = args.spaceKey
        config['spaceKey'] = args.spaceKey
        config.write()

    isIntranet = True
    PROXY_URL = config['PROXY_URL']
    proxy = None
    try:
        if args.OrangeSharing:
            try:
                JSESSIONID = config['JSESSIONID']
            except KeyError:
                JSESSIONID = ''

            if JSESSIONID == '':
                with Clip() as x:
                    JSESSIONID = x.paste()
                    print('OrangeSharing session token ' + JSESSIONID)
                config['JSESSIONID'] = JSESSIONID
                config.write()

            cookies = dict(JSESSIONID=JSESSIONID)
            proxy = {'proxy_url': PROXY_URL, 'proxy_user': user, 'proxy_pwd': pwd}
            email = config['email']
            url = config['url2']
            spaceKey = config['spaceKey2']

            # test if the proxy is reacheable.
            with CurlX(proxy=proxy) as requests:
                resp = requests.get(url=PROXY_URL)
            if 'Domain name not found' in resp.body:
                isIntranet = False
                print('Assuming on Internet')
                proxy = None

        else:
            url = config['url']
            spaceKey = config['spaceKey']

    except KeyError:
        print('missing keys in config file for OrangeSharing')
        url = 'https://confluence.europe.intranet/rest/api/content/'
        _exit(-1)

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

    if pwd is None and isIntranet:
        pwd = getpass('Enter password for user ' + user + ": ")
        if args.OrangeSharing:
            proxy = {'proxy_url': PROXY_URL, 'proxy_user': user, 'proxy_pwd': pwd}
        else:
            auth = (user, pwd)
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
        config['parentid'] = args.parentid
        config.write()
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
            if ".md" in f:
                print('file: ' + f)
                # title = f.replace('.wi', '')
                code = setConfluencePage(docPath, f, url, pageID, spaceKey, parentPageID, args.markdown)
                if code == 401:
                    print("Authorization failure!")
                    token = ''
                    config['token'] = ''
                    config.write()
                    _exit(1)
        _exit(0)

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

        code = setConfluencePage(docPath, f, url, pageID, spaceKey, parentPageID, args.markdown)
        if code == 401 or code == 403 or code == 404:
            print("Authorization failure!")
            if args.OrangeSharing:
                print("Don't forget to paste the JSESSIONID token in the clipboard")
            token = ''
            config['token'] = ''
            config['JSESSIONID'] = ''
            config.write()
            _exit(1)
        if code == 415:
            print("Please log on to OrangeSharing in Chrome & copy the JSESSIONID token to the clipboard")
            config['JSESSIONID'] = ''
            config.write()
            _exit(1)

        _exit(0)


def escapeRegExp(str):
    """
    This function escapes special characters in the str argument used in regular expressions
    and returns the modified string

    @param str: string
    @return: string
    """
    s = re.sub(r'([-\/\\^$*+?.()|[\]{}])', r'\\\1', str, 0)
    return s


def md_to_wiki(doc):
    """
    This routine converts MarkDown format to Confluence wiki format

    @param doc: string    the string containing the document to convert
    @return:    string    the converted document string
    """
    s = doc

    # escape curly braces to avoid entering Confluence macros
    s = re.sub(r'\{(.*)\}', r"\\{\1\\}", s, 0, re.M)

    # replace headers
    s = re.sub(r'^#####', 'h5. ', s, 0, re.M)
    s = re.sub(r'^####', 'h4. ', s, 0, re.M)
    s = re.sub(r'^###\s*(.*)\s*$', r'h3. {color:blue}\1{color}', s, 0, re.M)
    s = re.sub(r'^##\s*(.*)\s*$', r'h2. {color:blue}**\1**{color}', s, 0, re.M)
    s = re.sub(r'^#\s*(.*)\s*$', r'h1. {color:blue}**\1**{color}', s, 0, re.M)

    # replace bold - step 1
    s = re.sub(r'\*\*(.*?)\*\*', r'$$\1$$', s, 0)

    # replace italic
    s = re.sub(r'\*(.*?)\*', r'_\1_', s, 0)

    # replace bold - step 2
    s = re.sub(r'\$\$(.*?)\$\$', r'*\1*', s, 0)

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
        # header should have double | between columns
        header = re.sub(r'\|', '||', m[1], 0) + '||\n'
        s = re.sub(escapeRegExp(hdr) + r'\|\s*\n\|\s*-+\s*\|.*\n', header, s, 1)

    # image in .images folder
    pat = r'!\[(.*)\]\(.*.images.(.*)\s*.*?\)'
    s = re.sub(pat, r'!\2!', s)
    #    pat = r'!(.*)\)!'
    #    s = re.sub(pat, r'!\1!', s)

    # for m in re.finditer(pat, s):
    #     img = m[0]
    #     # replace '%20' by ' '
    #     img = m[2].replace('%20', ' ')
    #     # replace by confluence wiki
    #     s = re.sub(escapeRegExp(m[0]), r'!'+img+r'!', s)
    # .images in doc folder
    pat = r'!\[.*\]\((.*)\s*.*\)'
    for m in re.finditer(pat, s):
        img = m[0]
        # replace '%20' by ' '
        img = m[1].replace('%20', ' ')
        # replace by confluence wiki
        s = re.sub(escapeRegExp(m[0]), r'!' + img + r'|width=1000px!', s)
    # force image scape to 1000 pixels

    # links
    s = re.sub(r'(.*)\[(.*)\]\((.*)\)', r'\1[\2|\3]', s, 0, re.M)
    # update local references to ancors
    pat = r'\[(.*?)\|#.*?\]'
    for m in re.finditer(pat, s):
        lnk = re.sub(r' ', '', m[1], 0)
        s = re.sub(escapeRegExp(m[0]), '[' + m[1] + '|#' + lnk + ']', s, 1)

    # manage file://... attachments
    # the group between [ and | contains the file name without path
    pat = r'[^!]\[(.*)\|\s*file\:\/\/(.*)\/(.*?)\s*\]'

    for m in re.finditer(pat, s):
        # replace '%20' by ' '
        tag = m[1]
        lnk = m[3].replace('%20', ' ')

        attName = m[2] + r'\\' + m[3]
        attName = attName.replace('%20', ' ')
        attName = attName.replace('/', '\\')
        # convert avro schema files to uml drawing

        uml = avro_uml(attName)
        # replace by confluence wiki
        s = re.sub(escapeRegExp(m[0]), uml + r'\n[' + tag + '|^' + lnk + ']\n', s)

    # find code block
    # preceded by a file attachment corresponding to the code
    # pat = r'\[(.*)\.(.*)\^.*\]\n*```'
    pat = r'\[(.*?)\|\^(.*?)\.(.*?)\]\n*```(.*?)'
    rep = r'[\1|^\2.\3]\n\n{code:title=expand to see code for: ' \
          r'\1|linenumbers=true|language=\4|firstline=0001|collapse=true}\n{code} '
    s = re.sub(pat, rep, s, 0, re.M | re.VERBOSE)
    pat = r'\{code\}(.*?)```'
    # cb = re.search(pat, s, re.M|re.DOTALL).group(1)
    rep = r'\1\n{code}'
    s = re.sub(pat, rep, s, 0, re.M | re.DOTALL)

    # or just a simple code block with language tag
    pat = r'```(.*?)\n(.*?)```'
    rep = r'{code:title=expand to see code|linenumbers=true|language=\1|firstline=0001|collapse=true}\n\2\n{code}'
    s = re.sub(pat, rep, s, 0, re.M | re.DOTALL)

    # get rid of '|language=|' patterns
    pat = r'\|language=\|'
    rep = r'|'
    s = re.sub(pat, rep, s, 0, re.M | re.DOTALL)

    # find relationships paragraph with table and put it in an expand block
    pat = r'\*+(Relationships.*?)\*+\n*---\n(\|\|.*?\|)\n+---'
    rep = r'{expand:\1}\n\2\n{expand}\n'
    s = re.sub(pat, rep, s, 0, re.M | re.DOTALL)

    # find Table of Content and put it in an expand block
    pat = r'h2. {color:blue}_Table of Content_{color}(.*?)(h2. {color:blue}_Introduction)'
    rep = r'{expand:Table of Content}\n\1\n{expand}\n\2'
    s = re.sub(pat, rep, s, 0, re.M | re.DOTALL)
    if debug:
        print('-------------- wiki ----------------------')
        print(s)
        print('-------------- end wiki ----------------------')
    return s


def cname(data):
    # if 'namespace' in data:
    #    _classname = data['namespace']
    # el
    if 'name' in data:
        _classname = data['name']
    else:
        _classname = 'unknown'
    return _classname


def to_uml(data):
    """
    this routine converts an AVRO json file (as an object) to Plantuml code
    @param data: AVRO data object
    @return: Plantuml code
    """

    classname = ''
    try:
        # use the name space field or by default the name
        # as class name
        classname = cname(data)

        # declare the class
        uml = 'class ' + classname + ' {\n'
        uml2 = {}
        if 'doc' in data:
            d = "\t/' " + data['doc'] + " '/\n"
        else:
            d = '\n'
        # if of record type, add fields name as class field
        if data['type'] == 'record':
            for f in data['fields']:
                key = cname(f['type'])
                uml += '\t+' + f['name'] + ': '
                if 'doc' in f:
                    doc = "\t/' " + f['doc'] + " '/\n"
                else:
                    doc = '\n'
                # look for depending objects if AVRO type is complex
                if type(f['type']) is dict:

                    t = f['type']['type']
                    if 'doc' in f['type']:
                        ddoc = "\t/' " + f['type']['doc'] + " '/\n"
                    else:
                        ddoc = '\n'
                    # get the complex type (enum, array, map, record)
                    if type(t) is not dict:

                        if t == 'enum' or t == 'record':
                            uml += t + ddoc
                            u = to_uml(f['type'])
                            uml2[key] = u, t

                        elif t == 'array':
                            # array has items
                            i = f['type']['items']
                            if type(i) is dict:
                                uml += t + ddoc
                                u = to_uml(i)
                                uml2[key] = u, t
                            elif type(i) is list:
                                uml += t[0] + ' | null ' + ddoc
                            else:
                                uml += t + ' of ' + i + ddoc

                        elif t == 'map':
                            # array has values
                            i = f['type']['values']
                            if type(i) is dict:
                                uml += t + ddoc
                                u = to_uml(i)
                                uml2[key] = u, t
                            elif type(i) is list:
                                uml += t[0] + ' | null ' + ddoc
                            else:
                                uml += t + ' of ' + i + ddoc

                        else:
                            uml += t + doc

                    else:
                        # need to dig into that :-)
                        uml += 'object' + doc

                # optional field or null
                elif type(f['type']) is list:
                    uml += f['type'][0] + ' | null ' + doc
                # mandatory field
                else:
                    uml += f['type'] + doc

        elif data['type'] == 'enum':
            for f in data['symbols']:
                uml += '\t+' + f + d

        uml += '}\n'

        for k in uml2:
            u, t = uml2[k]
            uml += '\n' + u
            if t in ['enum', 'record']:
                uml += classname + ' -- ' + k + '\n'
            else:
                uml += classname + ' --|{ ' + k + '\n'
        return uml

    except KeyError as e:
        print(classname + ': Malformed AVRO file - missing key: ' + str(e))
        return ''


def avro_uml(file):
    doc = ''
    ext = file.split('.')[1]
    fpath = file[:-len(os.path.basename(file))]
    if ext == 'avsc':
        try:
            with open(file, 'r') as f:
                data = json.load(f)
            doc = '\n{plantuml}\n@startuml\nhide circle\nskinparam linetype ortho\n\n' + to_uml(
                data) + '\n@enduml\n{plantuml}\n'
            return (doc)
        except IOError:
            return ''
    elif ext == 'puml':
        try:
            with open(file, 'r') as f:
                data = f.read()
            # process include files in the .puml file
            pat = r'\!include (.*)'
            for m in re.finditer(pat, data):
                ifile = os.path.join(fpath, m[1])
                with open(ifile, 'r') as f:
                    idata = f.read()
                data = re.sub(escapeRegExp(m[0]), "' Include " + m[1] + '\n' + idata, data)
            # remove any directive from file
            data = re.sub(r'@.*', '', data)
            data = re.sub(r'skinparam.*', '', data)
            data = re.sub(r'hide circle.*', '', data)
            doc = '\n{plantuml}\n@startuml\nhide circle\nskinparam linetype ortho\n' + data + '\n@enduml\n{plantuml}\n'
            return (doc)
        except IOError:
            return ''
    return ''


def _exit(code):
    input('Press Enter to continue')
    sys.exit(code)


if __name__ == "__main__":
    main()
