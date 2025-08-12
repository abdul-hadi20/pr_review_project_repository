from django.shortcuts import render
from rest_framework import status
from django.http import StreamingHttpResponse
from rest_framework.views import APIView
from github import Github
from rest_framework.response import Response
from git import Repo
import os
import shutil
import hmac
import hashlib
from django.conf import settings
import openai
from openai import OpenAI
# GitHub Personal Access Token for API authentication

github_token=os.getenv('GITHUB_TOKEN')

# Secret key for verifying GitHub webhook signature

github_secret = os.getenv('GITHUB_SECRET').encode()

class Github_Pr_Review_Webhook(APIView):
    
    def signature_verification(self,request):
        """
        verify that the incommung webhook request is from github
        using HMAC sha256 signature 
        """
        
        #github send a header with the signature 
                #github send a header with the signature 

        header_signature=request.headers.get('X-Hub-Signature-256')
        
        if not header_signature:
            #if no signature found --> reject the request
            return False
        
        #it tell us the signature format is "sha256=<hash>"
        sha_name,signature=header_signature.split('=')
        
        if sha_name != 'sha256':
            #if used wrong algorithm --> reject it 
            return False
        
        #create our own hash using the secret and request body
        calculated_signature=hmac.new(github_secret,msg=request.body,digestmod=hashlib.sha256)
        
        #it compare the github signature with ours 
        return hmac.compare_digest(calculated_signature.hexdigest(),signature)
    
    def post(self,request):
        #it verifies the request signature
        # GitHub sends a special "X-Hub-Signature-256" header with each webhook request.
        # We check it using our secret key to make sure no one else is pretending to be GitHub.
        
        if not self.signature_verification(request):
            return Response({'error': 'Invalid signature'}, status=403)
        
        # Get the JSON payload GitHub sent.
        # This contains information like PR details, repository info, and the event type.
        payload=request.data
        
        # Identify what happened in the repository.
        # "action" tells us what kind of PR event this is ("opened", "closed", "edited", etc.).
        action=payload.get('action')
        
         # "pull_request" contains a big dictionary with all the PR’s details (author, branch, etc.).
        pr_information=payload.get('pull_request')
        
        if pr_information:
            if action not in ['opened','reopened','synchronize']:
                return Response({'msg':'this is not a new pr request'})
            else:
                # Get the repository's full name.
                repo_full_name=payload['repository']['full_name']
                
                # Get the PR number (e.g., PR #5).
                pr_number=pr_information['number']
                
                # Authenticate with GitHub using our personal access token.
                github=Github(github_token)
                
                # Get the repository object from GitHub API.
                repo=github.get_repo(repo_full_name)
                
                # Get the pull request object using its number.
                pr=repo.get_pull(pr_number)
                
                # Find the remote repository URL and branch for this PR.
                # clone_url → the HTTPS URL to clone the repo
                clone_url=pr.head.repo.clone_url
                
                # branch_name → the name of the branch containing the PR’s changes
                branch_name=pr.head.ref
                
                # Decide where on our computer we want to store this PR's code.
                local_path=f"/home/abdul-hadi/Documents/cloned_pr/pr_{pr_number}"
                
                # If the folder already exists (from an old clone), delete it first.
                if os.path.exists(local_path):
                    shutil.rmtree(local_path)   # Completely removes the folder and its files.
                # Clone the PR’s branch from GitHub into our local folder.
                Repo.clone_from(clone_url,local_path,branch=branch_name)
                
                openai_key = os.getenv("OPENAI_API_KEY")
                if not openai_key:
                    return Response({'error':'openai api key not found'},status=500)
                client = OpenAI(api_key=openai_key)
                
                pr_files=pr.get_files()
                pr_code=''
                for file in pr_files:
                    pr_code=pr_code+f"file:{file.filename}\n"
                    if file.patch:
                        pr_code=pr_code+file.patch + "\n"
                
                prompt=f"review the following pr code and give me feedback or commens\n {pr_code}"
                
                try:
                    response=client.chat.completions.create(
                        model='gpt-4o-mini',
                        messages=[
                            {'role':'system','content':'you are a helpful code review assistant'},
                            {'role':'user','content':prompt}
                        ],
                        max_tokens=500,
                        temperature=0.3
                    )

                    ai_review = response.choices[0].message.content
                    
                except Exception as e:
                    return Response({'msg':'cloned successfully but openai review failed'})
                
                return Response({
                    'msg':'Cloned successfully and reviewed by AI',
                    'ai_review':ai_review
                })
        
        else:
            return Response({'msg':'pr_info not found'})