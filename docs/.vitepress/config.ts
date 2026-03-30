import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'OpenSecCLI',
  description: 'One CLI for your entire security workflow',
  themeConfig: {
    logo: '/logo.svg',
    nav: [
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'Commands', link: '/guide/commands' },
      { text: 'Skills', link: '/guide/skills' },
      { text: 'API', link: '/api/cli-reference' },
    ],
    sidebar: [
      {
        text: 'Guide',
        items: [
          { text: 'Getting Started', link: '/guide/getting-started' },
          { text: 'Commands', link: '/guide/commands' },
          { text: 'Skills', link: '/guide/skills' },
          { text: 'Workflows', link: '/guide/workflows' },
          { text: 'MCP Integration', link: '/guide/mcp' },
          { text: 'Docker', link: '/guide/docker' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'CLI Reference', link: '/api/cli-reference' },
        ],
      },
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/skyvast404/OpenSecCLI' },
    ],
    footer: {
      message: 'Released under the Apache-2.0 License.',
    },
  },
})
