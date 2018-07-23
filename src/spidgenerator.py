MS_IDs = ["4284826+4284867"]
BID_IDs = ["BID-50523"]
NID_IDs = ["NID-66935"]
OSVDB_IDs = ["OSVDB-93646"]

CVE_IDs = ["CVE-2018-1221", "CVE-2017-11480", "CVE-2018-1002207"]
NPM_IDs = ["NPM-627"]

Snyk_IDs = [
    # Composer
    "SNYK-PHP-SYMFONYSYMFONY-72199", # CVE-2018-11408, CWE-601
    # Go
    "SNYK-GOLANG-CODECLOUDFOUNDRYORGGOROUTERROUTE-50074", # CVE-2018-1221, CWE-20
    # Maven
    "SNYK-JAVA-ORGJENKINSCIPLUGINS-32426", # CVE-2018-1000403, CWE-255
    # NPM
    "npm:cryptiles:20180710", # ref: https://snyk.io/vuln/npm:cryptiles:20180710
    "npm:memjs:20180627", # CVE-2018-3767, CWE-400
    # NuGet
    "SNYK-DOTNET-YAMLDOTNET-60255", # CVE-2018-1000210, CWE-94
    # PIP
    "SNYK-PYTHON-PYFTPDLIB-42147", # CVE-2007-6736, CWE-22
    # RubyGems
    "SNYK-RUBY-DOORKEEPER-22044", # CVE-2018-1000211, CWE-613, ref: https://snyk.io/vuln/SNYK-RUBY-DOORKEEPER-22044
    ]
Snyk_Sources = {
    "Composer": "C",
    "Go":       "G",
    "Maven":    "M",
    "npm":      "N",
    "NuGet":    "U",
    "pip":      "P",
    "RubyGems": "R"
}

Our_Sources = {
    "cve":  "C",
    "npm":  "N",
    "snyk": "S",
    "user": "U"
}

Years = {
    "2002": "02", "2003": "03", "2004": "04", "2005": "05",
    "2006": "06", "2007": "07", "2008": "08", "2009": "09",
    "2010": "10", "2011": "11", "2012": "12", "2013": "13",
    "2014": "14", "2015": "15", "2016": "16", "2017": "17",
    "2018": "18", "2019": "19", "2020": "20", "2021": "21"
}

# from scan_db import scan_database_for_snyk_ids
# from scan_db import connect_database
# from scan_db import disconnect_database

# connect_database()
# snyks_ids = scan_database_for_snyk_ids()
# disconnect_database()

import re
from datetime import datetime

Examples = [
    "SP-2018-C-071811408000",
    "SP-2018-S-057219900000",
    "SP-2018-S-082018062700",
    "SP-2018-N-021100000000",
    "SP-2018-U-011000000000"
]

SP_Prefix = "SP"
SP_Delimeter = "-"
SP_Max_Digits = 12

def Generate_ID(Original_ID, Source="CVE"):
    
    def Only_Digits(String):
        sis = re.sub(r"\D", "", String)
        return sis

    def Create_Set_Of_ID_Numbers(Numbers):
        Len_Of_Numbers = len(Numbers)
        Len_Of_Numbers_As_String = str(Len_Of_Numbers)
        Zeros = "0"*(SP_Max_Digits - Len_Of_Numbers)
        if Len_Of_Numbers < 10:
            Len_Of_Numbers_As_String = "0" + Len_Of_Numbers_As_String
        return "".join([Len_Of_Numbers_As_String, Numbers, Zeros]) 
        
    Current_Year = str(datetime.now().year)
    try:
        Src = Our_Sources[Source.lower()]
    except Exception as ex:
        print("Get wrong Source type: {}".format(Source))
        return ""
    if Src == "C":
        OI_As_List = Original_ID.split("-")
        if len(OI_As_List) == 3:
            CVE_Year = Years[OI_As_List[1]]
            CVE_Numbers = OI_As_List[2]
            CVE_Short_Year_And_Numbers = CVE_Year + CVE_Numbers
            Set_Of_CVE_Numbers = Create_Set_Of_ID_Numbers(CVE_Short_Year_And_Numbers)
            Our_ID = SP_Delimeter.join([SP_Prefix, Current_Year, Src, Set_Of_CVE_Numbers])
            return Our_ID
        else:
            return ""
    elif Src == "N":
        NPM_Year = Years[Current_Year]
        NPM_Numbers = Only_Digits(Original_ID)
        NPM_Short_Year_And_Numbers = NPM_Year + NPM_Numbers
        Set_Of_NPM_Numbers = Create_Set_Of_ID_Numbers(NPM_Short_Year_And_Numbers)
        Our_ID = SP_Delimeter.join([SP_Prefix, Current_Year, Src, Set_Of_NPM_Numbers])
        return Our_ID
    elif Src == "S":
        SNYK_Year = Years[Current_Year]
        if Original_ID.startswith("npm:"):
            Original_ID_Splitted = Original_ID.split(":")
            if len(Original_ID_Splitted) > 2:
                Original_ID_Numbers = Original_ID_Splitted[-1]
                SNYK_Numbers = Only_Digits(Original_ID_Numbers)
                if len(SNYK_Numbers) > 0:
                    SNYK_Short_Year_And_Numbers = SNYK_Year + SNYK_Numbers
                    Set_Of_SNYL_Numbers = Create_Set_Of_ID_Numbers(SNYK_Short_Year_And_Numbers)
                    Our_ID = SP_Delimeter.join([SP_Prefix, Current_Year, Src, Set_Of_SNYL_Numbers])
                    return Our_ID
                return ""
        else:
            Original_ID_Splitted = Original_ID.split("-")
            if len(Original_ID_Splitted) > 1:
                Original_ID_Numbers = Original_ID_Splitted[-1]
                SNYK_Numbers = Only_Digits(Original_ID_Numbers)
                if len(SNYK_Numbers) > 0:
                    SNYK_Short_Year_And_Numbers = SNYK_Year + SNYK_Numbers
                    Set_Of_SNYL_Numbers = Create_Set_Of_ID_Numbers(SNYK_Short_Year_And_Numbers)
                    Our_ID = SP_Delimeter.join([SP_Prefix, Current_Year, Src, Set_Of_SNYL_Numbers])
                    return Our_ID
                return ""
    elif Src == "U":
        User_Year = Years[Current_Year]
        User_Numbers = Only_Digits(Original_ID)
        User_Short_Year_And_Numbers = User_Year + User_Numbers
        Set_Of_User_Numbers = Create_Set_Of_ID_Numbers(User_Short_Year_And_Numbers)
        Our_ID = SP_Delimeter.join([SP_Prefix, Current_Year, Src, Set_Of_User_Numbers])
        return Our_ID
    else:
        return ""

print("\n")

Source = "CVE"

Original_ID = "CVE-2015-12211"
id = Generate_ID(Original_ID=Original_ID, Source=Source)
print("ID For Source {} With Original ID = {} will be {}".format(Source, Original_ID, id))

Source = "NPM"

Original_ID = "NPM-11"
id = Generate_ID(Original_ID=Original_ID, Source=Source)
print("ID For Source {} With Original ID = {} will be {}".format(Source, Original_ID, id))

Source = "SNYK"

Original_ID = "SNYK-GOLANG-GITHUBCOMMINIOMINIOCMD-50080"
id = Generate_ID(Original_ID=Original_ID, Source=Source)
print("ID For Source {} With Original ID = {} will be {}".format(Source, Original_ID, id))

Original_ID = "SNYK-PHP-SYMFONYSYMFONY-72199"
id = Generate_ID(Original_ID=Original_ID, Source=Source)
print("ID For Source {} With Original ID = {} will be {}".format(Source, Original_ID, id))

Original_ID = "SNYK-GOLANG-CODECLOUDFOUNDRYORGGOROUTERROUTE-50074"
id = Generate_ID(Original_ID=Original_ID, Source=Source)
print("ID For Source {} With Original ID = {} will be {}".format(Source, Original_ID, id))

Original_ID = "SNYK-JAVA-ORGJENKINSCIPLUGINS-32426"
id = Generate_ID(Original_ID=Original_ID, Source=Source)
print("ID For Source {} With Original ID = {} will be {}".format(Source, Original_ID, id))

Original_ID = "npm:cryptiles:20180710"
id = Generate_ID(Original_ID=Original_ID, Source=Source)
print("ID For Source {} With Original ID = {} will be {}".format(Source, Original_ID, id))

Original_ID = "SNYK-DOTNET-YAMLDOTNET-60255"
id = Generate_ID(Original_ID=Original_ID, Source=Source)
print("ID For Source {} With Original ID = {} will be {}".format(Source, Original_ID, id))

Original_ID = "SNYK-PYTHON-PYFTPDLIB-42147"
id = Generate_ID(Original_ID=Original_ID, Source=Source)
print("ID For Source {} With Original ID = {} will be {}".format(Source, Original_ID, id))

Original_ID = "SNYK-RUBY-DOORKEEPER-22044" 
id = Generate_ID(Original_ID=Original_ID, Source=Source)
print("ID For Source {} With Original ID = {} will be {}".format(Source, Original_ID, id))

Source = "User"
Original_ID = "1001"
id = Generate_ID(Original_ID=Original_ID, Source=Source)
print("ID For Source {} With Original ID = {} will be {}".format(Source, Original_ID, id))

print("\n")