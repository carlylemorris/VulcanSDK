import boto3
from botocore.exceptions import ClientError
import requests
import logging
from typing import Callable
import json
import time

logger = logging.getLogger()
logging.getLogger("botocore").setLevel(logging.DEBUG)
logging.getLogger("requests").setLevel(logging.DEBUG)


class Client:
    '''
    Wrapper class for interfacing with the Vulcan API
    '''
    @staticmethod
    def _filterDictionary(d: dict, filter: Callable[...,bool]=lambda v:bool(v)) -> dict:
        '''Removes key value pairs according to filter'''
        return {k:v for k,v in d.items() if filter(v)}

    @staticmethod
    def _get_vulcan_secret(secretName: str):

        secret_name = secretName
        region_name = "us-east-2"

        # Create a Secrets Manager client
        session = boto3.session.Session()
        client = session.client(
            service_name='secretsmanager',
            region_name=region_name
        )

        try:
            get_secret_value_response = client.get_secret_value(
                SecretId=secret_name
            )
        except ClientError as e:
            # For a list of exceptions thrown, see
            # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
            logger.error("Couldnt get API key from aws secrets manager")
            raise e

        # Decrypts secret using the associated KMS key.
        secret = get_secret_value_response['SecretString']

        # Your code goes here.
        return secret.split(":")[1][1:-2]


    def __init__(self, url: str, secretName: str):

        self.URL = url
        self.TOKEN = Client._get_vulcan_secret(secretName)
        self.HEADERS = {'Content-Type': 'application/json', 'Authorization': f'Bearer {self.TOKEN}'}

        self.session = requests.session()

        self.session.headers.update(self.HEADERS)


    def APIcall(self, method: str, resource: str, json: dict=None) -> dict:
        try:
            if json:
                r = self.session.request(method,f"{self.URL}/api/v1{resource}",json=json)
            else:
                r = self.session.request(method,f"{self.URL}/api/v1{resource}")
            
            rJson = r.json()

        except Exception as error:
            logger.error(f"Error in API request status {r.status_code}: {error}")
            raise


        if r.status_code == 429:
            i = 0
            while i < 5 and r.status_code == 429:
                delay = r.headers.get("Retry-After",1)
                logger.info(f"Backed off, Retry-After: {delay}")
                time.sleep(int(delay))
                if json:
                    r = self.session.request(method,f"{self.URL}/api/v1{resource}",json=json)
                else:
                    r = self.session.request(method,f"{self.URL}/api/v1{resource}")
                i +=1
                

            rJson = r.json()

        if r.status_code != 200:
            logger.error("API gave status code: "+str(r.status_code))
            raise RuntimeError("API gave status code: "+str(r.status_code))
        
        return rJson

    def tags(self) -> list:
        '''Get metadata about all tags. Less information than querying tags individually'''
        return self.APIcall("GET",f'/tags/')

    def tag(self,id: int) -> dict:
        '''Get all data about a single tag.'''
        return self.APIcall("GET",f'/tags/{id}/')
    
    def setTag(self, id: int, tagData: dict) -> dict:
        '''
        Change entire tag to tagData

        id : int - tagID
        tagData : dict - data for tag, if a field is omitted it appears to be left unchanged.

        returns pre-change state of tag
        '''
        rJson = self.APIcall("PUT",f"/tags/{id}/",json=tagData)
        return rJson


    def setTagImpact(self,id: int, impact : int) -> dict:
        '''Set impact level of tag, return original data of tag
        
        id : int - tag id to change
        impact: int - impact level
            0 -> unassigned
            1 -> low
            2 -> medium
            3 -> high
        
        returns original data of tag before change
        '''
        dataDelta = {"severity_score": impact}

        resp = self.setTag(id,dataDelta)

        logger.debug(f"Changing {id} from {resp} to {dataDelta}")

        return resp

    def _queryAssets(self,
                    assetType:str,
                    sort_by:list[dict], 
                    freeInput:list[str], 
                    source:list[str], 
                    tags:list[str], 
                    excludeTags:list[str],
                    business_group_id:int,
                    first_row:int,
                    end_row:int,
                    **kwargs:dict) -> dict:
        '''
        query all instances of an asset

        sort_by - unknown
        freeInput - list of text inputs to search by union for
        source - list of sources to search by union for
        tags - list of tags to search by union for
        exclude tags - list of tags to exclude in results
        business_group_id - id to search by business group
        first_row - first record to return default 0
        end_row - last record to return default 10
        **kwargs - extra query info to be included in the query

        returns asset data dict
        '''
        try:
            json = kwargs
            json.update({      
                "first_row": first_row,
                "end_row": end_row,
            })

            assetFilter = {
                "freeInput": freeInput,
                "Source": source,
                "Tags" : tags,
                "Exclude Tags": excludeTags
            }
            #Note: the vulcan API requires this data structure to be called filter for asset endpoints and filters for vulnerability endpoints
            json["filter"] = json.get("filters",dict())
            json["filter"].update(self._filterDictionary(assetFilter,lambda v: not v is None))

            if not sort_by is None:
                json["sort_by"] = sort_by
            if not business_group_id is None:
                json["business_group_id"] = business_group_id

            rJson = self.APIcall("POST",f"/assets/{assetType}/",json=self._filterDictionary(json))

        except Exception as e:
            logger.error(e)
            rJson = dict()

        return rJson

    def hosts(self,
              sort_by:list[dict]=None, 
              freeInput:list[str]=None, 
              source:list[str]=None, 
              tags:list[str]=None, 
              excludeTags:list[str]=None,
              business_group_id:int=None,
              first_row:int = 0,
              end_row:int = 10,
              **kwargs:dict) -> dict:
        '''
        Query all Hosts

        sort_by - unknown
        freeInput - list of text inputs to search by union for
        source - list of sources to search by union for
        tags - list of tags to search by union for
        exclude tags - list of tags to exclude in results
        business_group_id - id to search by business group
        first_row - first record to return default 0
        end_row - last record to return default 10

        returns host data dict
        '''
        return self._queryAssets("hosts",
                                sort_by=sort_by,
                                freeInput=freeInput,
                                source=source,
                                tags=tags,
                                excludeTags=excludeTags,
                                business_group_id=business_group_id,
                                first_row=first_row,
                                end_row=end_row,
                                **kwargs)
    

    def host(self,assetID:int) -> dict:
        '''
        Query for individual host by id
        '''
        return self.APIcall("GET",f"/assets/hosts/{assetID}/")
    
    def code_projects(self, 
              sort_by:list[dict]=None, 
              freeInput:list[str]=None, 
              source:list[str]=None, 
              tags:list[str]=None, 
              excludeTags:list[str]=None,
              business_group_id:int=None,
              first_row:int = 0,
              end_row:int = 10,
              **kwargs:dict) -> dict:
        '''
        Query all Code Projects

        sort_by - unknown
        freeInput - list of text inputs to search by union for
        source - list of sources to search by union for
        tags - list of tags to search by union for
        exclude tags - list of tags to exclude in results
        business_group_id - id to search by business group
        first_row - first record to return default 0
        end_row - last record to return default 10

        returns Code Project data dict
        '''
        return self._queryAssets("code_projects",
                                sort_by=sort_by,
                                freeInput=freeInput,
                                source=source,
                                tags=tags,
                                excludeTags=excludeTags,
                                business_group_id=business_group_id,
                                first_row=first_row,
                                end_row=end_row,
                                **kwargs)
    
    def code_project(self, assetID:int) -> dict:
        '''
        Query for individual Code Project by id
        '''
        return self.APIcall("GET",f"/assets/code_projects/{assetID}/")
    
    def images(self, 
              sort_by:list[dict]=None, 
              freeInput:list[str]=None, 
              source:list[str]=None, 
              tags:list[str]=None, 
              excludeTags:list[str]=None,
              business_group_id:int=None,
              first_row:int = 0,
              end_row:int = 10,
              **kwargs) -> dict:
        '''
        Query all Images

        sort_by - unknown
        freeInput - list of text inputs to search by union for
        source - list of sources to search by union for
        tags - list of tags to search by union for
        exclude tags - list of tags to exclude in results
        business_group_id - id to search by business group
        first_row - first record to return default 0
        end_row - last record to return default 10

        returns Image data dict
        '''
        return self._queryAssets("repositories",
                                sort_by=sort_by,
                                freeInput=freeInput,
                                source=source,
                                tags=tags,
                                excludeTags=excludeTags,
                                business_group_id=business_group_id,
                                first_row=first_row,
                                end_row=end_row,
                                **kwargs)

    def image(self, assetID:int) -> dict:
        '''
        Query for individual Image by id
        '''
        return self.APIcall("GET",f"/assets/repositories/{assetID}/")

    def cloud_resources(self, 
                        sort_by:list[dict]=None, 
                        freeInput:list[str]=None, 
                        source:list[str]=None, 
                        tags:list[str]=None, 
                        excludeTags:list[str]=None,
                        business_group_id:int=None,
                        first_row:int = 0,
                        end_row:int = 10,
                        **kwargs) -> dict:
        '''
        Query all Cloud Resources

        sort_by - unknown
        freeInput - list of text inputs to search by union for
        source - list of sources to search by union for
        tags - list of tags to search by union for
        exclude tags - list of tags to exclude in results
        business_group_id - id to search by business group
        first_row - first record to return default 0
        end_row - last record to return default 10

        returns Cloud Resources data dict
        '''
        return self._queryAssets("cloud_resources",
                                sort_by=sort_by,
                                freeInput=freeInput,
                                source=source,
                                tags=tags,
                                excludeTags=excludeTags,
                                business_group_id=business_group_id,
                                first_row=first_row,
                                end_row=end_row,
                                **kwargs)

    def cloud_resource(self, assetID:int) -> dict:
        '''
        Query for individual Image by id
        '''
        return self.APIcall("GET",f"/assets/cloud_resources/{assetID}/")

    def websites(self, 
                        sort_by:list[dict]=None, 
                        freeInput:list[str]=None, 
                        source:list[str]=None, 
                        tags:list[str]=None, 
                        excludeTags:list[str]=None,
                        business_group_id:int=None,
                        first_row:int = 0,
                        end_row:int = 10,
                        **kwargs) -> dict:
        '''
        Query all Websites

        sort_by - unknown
        freeInput - list of text inputs to search by union for
        source - list of sources to search by union for
        tags - list of tags to search by union for
        exclude tags - list of tags to exclude in results
        business_group_id - id to search by business group
        first_row - first record to return default 0
        end_row - last record to return default 10

        returns Websites data dict
        '''
        return self._queryAssets("websites",
                                sort_by=sort_by,
                                freeInput=freeInput,
                                source=source,
                                tags=tags,
                                excludeTags=excludeTags,
                                business_group_id=business_group_id,
                                first_row=first_row,
                                end_row=end_row,
                                **kwargs)

    def website(self, assetID:int) -> dict:
        '''
        Query for individual Image by id
        '''
        return self.APIcall("GET",f"/assets/websites/{assetID}/")

    def vulns(self,
            sort_by:dict=None,
            freeInput:list[str]=None,
            priority:list[int]=None,
            vuln_sources:list[str]=None,
            assets_os_versions:list[str]=None,
            threats:list[str]=None,
            operatingSystems:list[str]=None,
            cves:list[str]=None,
            cvss_score_min:float=None,
            cvss_score_max:float=None,
            vulcan_discovery_time:dict=None,
            sla_status:list[str]=None,
            assets_sources:list[str]=None,
            sccm_patchable:list[str]=None,
            tags:list[str]=None,
            exclude_tags:list[str]=None,
            tableStatus:list[str]=None,
            biz_group_id:int=None,
            first_row:int=None,
            end_row:int=None,
            **kwargs) -> dict:
        """
        Retrieve a list of vulnerabilities based on various filters and parameters.

        sort_by (dict): A dictionary specifying the sorting criteria for the results.
        freeInput (list[str]): A list of search terms to filter vulnerabilities.
        priority (list[int]): A list of integers representing vulnerability priorities.
        vuln_sources (list[str]): A list of strings specifying vulnerability sources.
        assets_os_versions (list[str]): A list of strings representing asset OS versions.
        threats (list[str]): A list of strings specifying threat types.
        operatingSystems (list[str]): A list of strings representing operating systems.
        cves (list[str]): A list of strings representing CVEs
        cvss_score_min (float): Minimum CVSS score for filtering vulnerabilities.
        cvss_score_max (float): Maximum CVSS score for filtering vulnerabilities.
        vulcan_discovery_time (dict): A dictionary specifying the discovery time range.
        sla_status (list[str]): A list of strings representing SLA statuses.
        assets_sources (list[str]): A list of strings representing asset sources.
        sccm_patchable (list[str]): A list of strings indicating SCCM patchable status.
        tags (list[str]): A list of strings to filter vulnerabilities by tags.
        exclude_tags (list[str]): A list of strings to exclude vulnerabilities by tags.
        tableStatus (list[str]): A list of strings representing table status values.
        biz_group_id (int): An integer representing the business group ID for filtering.
        first_row (int): Integer specifying the first row index for paginated results.
        end_row (int): Integer specifying the last row index for paginated results.
        **kwargs: Additional keyword arguments for future extensibility.

        The vulns() method reaches an endpoint that classifies risk level (priority) differently than the Vulcan GUI. If you need an apples to apples risk score comparison use risks()
        """        

        try:
            json = kwargs
            json.update({   
                "start_offset": first_row,
                "end_offset": end_row,
            })

            if not sort_by is None:
                json["sort_by"] = sort_by
            if not biz_group_id is None:
                json["biz_group_id"] = biz_group_id

            vulnFilter = {
                "freeInput":freeInput,
                "priority":priority,
                "vuln_sources":vuln_sources,
                "assets_os_versions":assets_os_versions,
                "threats":threats,
                "operatingSystems":operatingSystems,
                "cves":cves,
                "vulcan_discovery_time":vulcan_discovery_time,
                "sla_status":sla_status,
                "assets_sources":assets_sources,
                "sccm_patchable":sccm_patchable,
                "Tags":tags,
                "Exclude_tags":exclude_tags,
                "tableStatus":tableStatus
            }

            if not cvss_score_min is None:
                vulnFilter["cvss_score"] = [{"op":"gte","value":cvss_score_min}]

            if not cvss_score_max is None:
                vulnFilter["cvss_score"] = vulnFilter.get("cvss_score",list())
                vulnFilter["cvss_score"].append({"op":"lte","value":cvss_score_max})

            #Note: the vulcan API requires this data structure to be called filter for asset endpoints and filters for vulnerability endpoints
            json["filters"] = json.get("filters",dict())
            json["filters"].update(self._filterDictionary(vulnFilter,lambda v: not v is None))

            rJson = self.APIcall("POST",f"/vulnerabilities/",json=json)

        except Exception as e:
            logger.error(e)
            rJson = dict()

        return rJson
    
    def vuln(self,id:int)->dict:
        """Query individual vulnerability by id

        Provides the most amound of detail but is rate limited to 60 seconds
        """

        return self.APIcall("POST",f"/vulnerabilities/details/{id}/")
    
    def risks(self,
              first_row:int=None,
              end_row:int=None,
              cvss_score_min:float=0.0,
              cvss_score_max:float=10.0) -> dict:
        '''
        Return a dict of all vulnerabilities and their priority/max risk.

        WARNING: this function uses an undocumented API endpoint
        '''
        try:
            body = {
                "biz_group_id":[],
                "category":"vulnerable",
                "filters":{
                    "cvss_score":[
                        {
                            "op":"gte",
                            "value":cvss_score_min
                        },
                        {
                            "op":"lte",
                            "value":cvss_score_max
                        }
                    ]
                },
                "start_offset":first_row,
                "end_offset":end_row,
                "sort_by":[
                    {
                        "colId":"priority",
                        "sort":"desc"
                    }
                ]
            }

            r = self.session.request("POST",f"{self.URL}/api/asset_manager/vulnerability/v4/get_vulnerabilities_data/",json=body)
        
            rJson = r.json()
        except Exception as e:
            logger.error(e)
            raise e
        
        return rJson


class readOnlyClient(Client):

    '''Read only subclass to prevent unintentional write operations during testing and reporting'''
    
    def setTag(self, id: int, tagData: dict) -> dict:
        raise NotImplementedError("Cant make modifying call to Vulcan API from readOnlyClient")
    
    def setTagImpact(self, id: int, impact: int) -> dict:

        logger.info(f"{id} set to {impact}")

        return {}