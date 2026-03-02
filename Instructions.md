## 1. Clone or Download the Repository

### Option A – Clone via Git
```
git clone https://github.com/YOUR_USERNAME/llm-privacy-guard.git
cd llm-privacy-guard
```

### Option B – Download ZIP
Click Code → Download ZIP
Extract
Open folder in VS Code

## 2. Install TypeScript
From project root:
```
PS: npm install --save-dev typescript
```

## 3. Compile TypeScript
```
PS: npx tsc
```
This generates:
```
content.js
```

## 4.  Load Extension in Microsoft Edge or Chrome (or Other browser)
Open: extensions on your browser 
```
edge //extensions
```
Enable Developer Mode
Click Load Unpacked
Select your project folder
Click Reload if needed

## 5. Test it
Open:
https://chatgpt.com/
Paste:
```
Here is my key: sk-1234567890abcdef1234567890abcdef
```
Press Enter
You should see the Privacy Guard modal.
Nothing will be sent until you choose:
Redact & Continue
Proceed Anyway
Cancel
