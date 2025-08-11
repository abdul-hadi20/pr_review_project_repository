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

# GitHub Personal Access Token for API authentication


github_token=os.getenv('GITHUB_TOKEN')
print('github_token:',github_token)

# Secret key for verifying GitHub webhook signature

github_secret = os.getenv('GITHUB_SECRET').encode()
print('github_secret:',github_secret)

class Github_Pr_Review_Webhook(APIView):
    
    def signature_verification(self,request):
        """
        verify that the incommung webhook request is from github
        using HMAC sha256 signature 
        """
        
        #github send a header with the signature 
                #github send a header with the signature 

        header_signature=request.headers.get('X-Hub-Signature-256')
        print('header_signature',header_signature)
        if not header_signature:
            #if no signature found --> reject the request
            return False
        print('if condition of header_signature')
        
        #it tell us the signature format is "sha256=<hash>"
        sha_name,signature=header_signature.split('=')
        print('sha_name:',sha_name)
        if sha_name != 'sha256':
            #if used wrong algorithm --> reject it 
            return False
        print('if condition of sha name')
        
        #create our own hash using the secret and request body
        calculated_signature=hmac.new(github_secret,msg=request.body,digestmod=hashlib.sha256)
        print('calculated_signature:',calculated_signature)
        
        #it compare the github signature with ours 
        return hmac.compare_digest(calculated_signature.hexdigest(),signature)
    
    def post(self,request):
        #it verifies the request signature
        # GitHub sends a special "X-Hub-Signature-256" header with each webhook request.
        # We check it using our secret key to make sure no one else is pretending to be GitHub.
        print('post method starts')
        
        if not self.signature_verification(request):
            return Response({'error': 'Invalid signature'}, status=403)
        
        print('if condition of signature verification in post ')
        
        # Get the JSON payload GitHub sent.
        # This contains information like PR details, repository info, and the event type.
        payload=request.data
        print('payload:',payload)
        
        
        # Identify what happened in the repository.
        # "action" tells us what kind of PR event this is ("opened", "closed", "edited", etc.).
        action=payload.get('action')
        print('action:',action)
        
         # "pull_request" contains a big dictionary with all the PR’s details (author, branch, etc.).
        pr_information=payload.get('pull_request')
        print('pr_information:',pr_information)
        
        if pr_information:
            print('if condition of pr information')
            if action != ['opened','reopened','synchronize']:
                
                print('if condition of action check')
                
                return Response({'msg':'this is not a new pr request'})
            else:
                print('else of action check')
                # Get the repository's full name.
                repo_full_name=payload['repository']['full_name']
                print('repo_full_name',repo_full_name)
                
                # Get the PR number (e.g., PR #5).
                pr_number=pr_information['number']
                print('pr_number',pr_number)
                
                # Authenticate with GitHub using our personal access token.
                github=Github(github_token)
                print('github',github)
                
                # Get the repository object from GitHub API.
                repo=github.get_repo(repo_full_name)
                print('repo:',repo)
                
                # Get the pull request object using its number.
                pr=repo.get_pull(pr_number)
                print('pr',pr)
                
                # Find the remote repository URL and branch for this PR.
                # clone_url → the HTTPS URL to clone the repo
                clone_url=pr.head.repo.clone_url
                print('clone url',clone_url)
                
                # branch_name → the name of the branch containing the PR’s changes
                branch_name=pr.head.ref
                print('branch_name',branch_name)
                
                # Decide where on our computer we want to store this PR's code.
                local_path=f"/home/abdul-hadi/Documents/task/pr/pr_{pr_number}"
                print('local_path',local_path)
                
                # If the folder already exists (from an old clone), delete it first.
                if os.path.exists(local_path):
                    shutil.rmtree(local_path)   # Completely removes the folder and its files.
                    print('if condition of os module')
                # Clone the PR’s branch from GitHub into our local folder.
                Repo.clone_from(clone_url,local_path,branch=branch_name)
                print('cloneed')
                
                return Response({'msg':'cloned successfuly'})
        
        else:
            print('else of pr info if')
            return Response({'msg':'pr_info not found'})