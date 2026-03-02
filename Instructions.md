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


## Project Structure

llm-privacy-guard/
│
├── src/manifest.json
├── src/content.ts
├── src/content.js (generated from npx tsc)
├── src/tsconfig.json
├── TEST_PLAN.md
├── Instructions.md
└── README.md

## 🧠 Design Principles
Zero trust for outbound prompts  
Least privilege  
High-signal detection only (low false positives)  
No black box  
Fully local  

## 🔮 Future Enhancements

Hard block mode for BLOCK findings  
Per-site allowlist  
Toggle in extension popup  
Enterprise policy-as-code support  
Support for additional LLM sites  
Centralized logging (optional enterprise mode)  

## ⚠️ Known Limitations (MVP)

Currently optimized for chatgpt.com  
DOM selectors may require updates if UI changes  
Does not scan file uploads  
No server-side protection (browser-only)  

## 📜 License

MIT License

## 🙌 Contributing

Fork the repo  
Create feature branch  
Submit PR  

## 🛡️ Disclaimer

This is a lightweight privacy guard tool.  
It reduces accidental leakage of secrets but does not replace enterprise DLP systems.  


