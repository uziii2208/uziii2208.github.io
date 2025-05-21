# uziii2208.github.io

A serverless blog for a security engineer to share CTF write-ups and cybersecurity knowledge. Features a dark theme with green accents, inspired by https://benheater.com/ and https://4xura.com/.

## Features

- Responsive design with dark/light theme toggle
- Six main sections: About Me, HackTheBox, TryHackMe, Blogs, Contact, and Complaints
- Integration with Notion for content management
- Serverless contact forms using Formspree
- Modern UI with TailwindCSS and JetBrains Mono font

## Setup Instructions

1. Create a GitHub repository:
   ```bash
   git clone https://github.com/uziii2208/uziii2208.github.io.git
   cd uziii2208.github.io
   ```

2. Set up Formspree integration:
   - Sign up at https://formspree.io/
   - Create two new forms (one for Contact, one for Complaints)
   - Replace `{FORM_ID}` in `pages/contact.html` and `pages/complaints.html` with your form IDs

3. Export content from Notion:
   - In Notion, navigate to the page you want to export
   - Click "..." > Export > HTML
   - Convert the exported HTML to match the site's styling:
     - Add the standard navigation bar from other pages
     - Add TailwindCSS and custom styles
     - Include metadata in `<meta>` tags
   - Place the converted files in the appropriate folders:
     - HackTheBox write-ups: `content/hackthebox/`
     - TryHackMe write-ups: `content/tryhackme/`
     - Blog posts: `content/blogs/`

4. Update post metadata:
   - Open `js/main.js`
   - Add new posts to the appropriate section in the `sections` object
   - Include title, excerpt, URL, and date for each post

5. Deploy to GitHub Pages:
   ```bash
   git add .
   git commit -m "Initial commit"
   git push origin main
   ```

6. Enable GitHub Pages:
   - Go to repository Settings > Pages
   - Set source branch to `main`
   - Save changes
   - Your site will be available at `https://uziii2208.github.io`

## Development

### Local Development
1. Install a local web server (e.g., Live Server VS Code extension)
2. Preview changes locally before pushing to GitHub

### File Structure
```
uziii2208.github.io/
├── index.html
├── css/
│   └── styles.css
├── js/
│   └── main.js
├── pages/
│   ├── about.html
│   ├── hackthebox.html
│   ├── tryhackme.html
│   ├── blogs.html
│   ├── contact.html
│   └── complaints.html
├── content/
│   ├── hackthebox/
│   ├── tryhackme/
│   └── blogs/
└── assets/
```

### Adding New Content
1. Export content from Notion as HTML
2. Convert to match site styling:
   ```html
   <!DOCTYPE html>
   <html lang="en">
   <head>
       <meta charset="UTF-8">
       <meta name="viewport" content="width=device-width, initial-scale=1.0">
       <title>Post Title - Section</title>
       <meta name="description" content="Post description">
       <meta name="date" content="YYYY-MM-DD">
       <meta name="author" content="UZIII">
       <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
       <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
       <link href="../../css/styles.css" rel="stylesheet">
   </head>
   <body>
       <!-- Copy navigation from another post -->
       <!-- Add your content here -->
       <!-- Copy footer from another post -->
   </body>
   </html>
   ```
3. Update metadata in `js/main.js`
4. Commit and push changes

## Customization

### Theme Colors
- Edit colors in `css/styles.css`
- Default theme uses:
  - Background: `bg-gray-900`
  - Text: `text-gray-100`
  - Accents: `text-green-400`

### Typography
- Site uses JetBrains Mono font
- To change, update font in `css/styles.css` and font import in HTML files

### Layout
- Built with TailwindCSS utility classes
- Responsive design with mobile-first approach
- Edit classes in HTML files to modify layout

## Contributing

1. Fork the repository
2. Create a new branch: `git checkout -b feature-name`
3. Make changes and commit: `git commit -m "Add feature"`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

## License

This project is open source and available under the MIT License.

## Contact

For questions or issues:
- Use the Contact form on the website
- Submit an issue on GitHub
