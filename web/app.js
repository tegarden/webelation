const createVaultApp = () => ({
    data: [],
    selectedId: null,
    selectedFile: null,
    fileName: "",
    pendingPassword: "",
    passwordDialogFileName: "",
    showPassword: false,
    isBusy: false,
    statusMessage: "Loading WebAssembly parser...",
    expanded: {},
    parseRevelation: null,

    init() {
      this.initWasm();
    },

    get tree() {
      const rows = [];

      const walk = (nodes, depth) => {
        nodes.forEach((node) => {
          rows.push({ ...node, depth });
          if (node.children?.length && this.expanded[node.id]) {
            walk(node.children, depth + 1);
          }
        });
      };

      walk(this.data, 0);
      return rows;
    },

    get selectedEntry() {
      const findById = (nodes, id) => {
        for (const node of nodes) {
          if (node.id === id && node.nodeType === "entry") {
            return node;
          }
          if (node.children?.length) {
            const match = findById(node.children, id);
            if (match) {
              return match;
            }
          }
        }
        return null;
      };

      return findById(this.data, this.selectedId);
    },

    async initWasm() {
      try {
        const wasm = await import("./webelation_wasm.js");
        await wasm.default();
        this.parseRevelation = wasm.parse_revelation;
        this.statusMessage = "Select a Revelation file.";
      } catch (error) {
        this.statusMessage = "Failed to load the WebAssembly bundle. Build rust/pkg first.";
        console.error(error);
      }
    },

    async handleFilePick(event) {
      const file = event.target.files?.[0] ?? null;
      this.selectedFile = file;
      this.fileName = file?.name ?? "";
      event.target.value = "";

      if (!file) {
        this.data = [];
        this.selectedId = null;
        this.statusMessage = "Select a Revelation file.";
        return;
      }

      this.pendingPassword = "";
      this.passwordDialogFileName = file.name;
      this.statusMessage = `Selected ${file.name}. Waiting for password.`;
      this.$refs.passwordDialog.showModal();

      await this.$nextTick();
      this.$refs.passwordInput?.focus();
    },

    normalizeNode(node) {
      const children = Array.isArray(node.children)
        ? node.children.map((child) => this.normalizeNode(child))
        : [];

      return {
        id: String(node.id),
        nodeType: node.nodeType === "folder" ? "folder" : "entry",
        type: node.type ?? "",
        label: node.label ?? node.title ?? "Untitled",
        title: node.title ?? node.label ?? "Untitled",
        description: node.description ?? null,
        username: node.username ?? null,
        password: node.password ?? null,
        url: node.url ?? null,
        notes: node.notes ?? null,
        children,
      };
    },

    setParsedEntries(entries) {
      this.data = Array.isArray(entries) ? entries.map((entry) => this.normalizeNode(entry)) : [];
      this.expanded = {};

      const expandFolders = (nodes) => {
        nodes.forEach((node) => {
          if (node.children.length) {
            this.expanded[node.id] = true;
            expandFolders(node.children);
          }
        });
      };

      expandFolders(this.data);
      this.selectedId = this.findFirstEntryId(this.data);
      this.showPassword = false;
    },

    findFirstEntryId(nodes) {
      for (const node of nodes) {
        if (node.nodeType === "entry") {
          return node.id;
        }
        if (node.children.length) {
          const childId = this.findFirstEntryId(node.children);
          if (childId) {
            return childId;
          }
        }
      }
      return null;
    },

    closePasswordDialog() {
      if (this.$refs.passwordDialog?.open) {
        this.$refs.passwordDialog.close();
      }
    },

    async reopenPasswordPrompt(statusMessage) {
      if (!this.selectedFile) {
        return;
      }

      this.pendingPassword = "";
      this.passwordDialogFileName = this.selectedFile.name;
      this.statusMessage = statusMessage;
      this.$refs.passwordDialog.showModal();

      await this.$nextTick();
      this.$refs.passwordInput?.focus();
    },

    cancelPasswordPrompt() {
      const cancelledFile = this.passwordDialogFileName || this.fileName;
      this.pendingPassword = "";
      this.passwordDialogFileName = "";
      this.closePasswordDialog();
      this.statusMessage = cancelledFile
        ? `Password entry canceled for ${cancelledFile}.`
        : "Password entry canceled.";
    },

    async submitPasswordPrompt() {
      if (!this.pendingPassword) {
        this.statusMessage = "Enter the vault password first.";
        await this.$nextTick();
        this.$refs.passwordInput?.focus();
        return;
      }

      const password = this.pendingPassword;
      this.pendingPassword = "";
      this.passwordDialogFileName = "";
      this.closePasswordDialog();
      await this.parseSelectedFile(password);
    },

    async parseSelectedFile(password) {
      if (!this.parseRevelation) {
        this.statusMessage = "The WebAssembly parser is not available yet.";
        return;
      }

      if (!this.selectedFile) {
        this.statusMessage = "Choose a Revelation file first.";
        return;
      }

      if (!password) {
        this.statusMessage = "Enter the vault password first.";
        return;
      }

      this.isBusy = true;
      this.statusMessage = `Parsing ${this.selectedFile.name}...`;

      try {
        const buffer = await this.selectedFile.arrayBuffer();
        const raw = this.parseRevelation(new Uint8Array(buffer), password);
        const parsed = JSON.parse(raw);

        if (parsed.error) {
          this.data = [];
          this.selectedId = null;
          await this.reopenPasswordPrompt(`Parse failed: ${parsed.error}`);
          return;
        }

        this.setParsedEntries(parsed.entries ?? []);
        this.statusMessage = this.data.length
          ? `Loaded ${this.selectedFile.name}.`
          : `Loaded ${this.selectedFile.name}, but it contains no entries.`;
      } catch (error) {
        this.data = [];
        this.selectedId = null;
        await this.reopenPasswordPrompt("The selected file could not be parsed.");
        console.error(error);
      } finally {
        this.isBusy = false;
      }
    },

    toggleNode(node) {
      if (!node.children?.length) {
        return;
      }
      this.expanded[node.id] = !this.expanded[node.id];
    },

    selectNode(node) {
      if (node.children?.length) {
        this.expanded[node.id] = true;
      }
      if (node.nodeType === "entry") {
        this.selectedId = node.id;
        this.showPassword = false;
      }
    },

    maskedPassword(password) {
      return password ? "*".repeat(Math.max(8, password.length)) : "—";
    },

    async copyPassword() {
      if (!this.selectedEntry?.password) {
        this.statusMessage = "No password available to copy.";
        return;
      }

      try {
        await navigator.clipboard.writeText(this.selectedEntry.password);
        this.statusMessage = `Copied password for ${this.selectedEntry.title}.`;
      } catch (_) {
        this.statusMessage = "Clipboard access failed in this context.";
      }
    },
  });

window.vaultApp = createVaultApp;
