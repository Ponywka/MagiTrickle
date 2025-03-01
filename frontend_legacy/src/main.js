import "./style.css";

function createElement(tag, attributes = {}, innerHTML = "") {
    const element = document.createElement(tag);
    Object.entries(attributes).forEach(([key, value]) => {
        element.setAttribute(key, value)
    });
    element.innerHTML = innerHTML;
    return element;
};

function showOverlay() {
    document.querySelector("#overlay").style.display = "block";
}

function hideOverlay() {
    document.querySelector("#overlay").style.display = "none";
}

class App {
    API_BASE = "/api/v1";

    root;
    groupsElement;
    interfaces;

    constructor(element) {
        this.root = element;
        this.root.innerHTML = ``+
            `<div class="container">`+
                `<h1>MagiTrickle (Legacy WebUI)</h1>`+
                `<button id="btnFetchGroups">Обновить список</button><button id="btnSaveConfig">Сохранить текущую конфигурацию</button><br/>`+
                `<div id="groups"></div>`+
                `<h2>Создать группу</h2>`+
                `<label for="groupCreateName">Имя группы:</label><input id="groupCreateName"><br/>`+
                `<label for="groupCreateInterface">Интерфейс:</label><select id="groupCreateInterface"></select><br/>`+
                `<label for="groupCreateEnable">Активировать группу</label><input id="groupCreateEnable" type="checkbox"><br/>`+
                `<button id="btnCreateGroup">Создать</button>`+
            `</div>`+
        ``;
        this.root.querySelector("#btnFetchGroups").onclick = () => this.fetchGroups();
        this.root.querySelector("#btnSaveConfig").onclick = () => this.saveConfig();
        this.root.querySelector("#btnCreateGroup").onclick = () => this.createGroup();
        this.groupsElement = this.root.querySelector("#groups");
        const _root = this;
        (async function () {
            _root.interfaces = await _root.fetchInterfaces();
            _root.populateInterfaces(_root.root.querySelector("#groupCreateInterface"), _root.interfaces);
            await _root.fetchGroups()
        })()
    }

    populateInterfaces(interfacesSelect, interfaces, selectedInterface = null) {
        interfaces.forEach(iface => {
            const option = createElement("option", {
                value: iface,
            }, iface)
            if (iface === selectedInterface) {
                option.selected = true
            }
            interfacesSelect.appendChild(option);
        });
        if (selectedInterface !== null && !interfaces.includes(selectedInterface)) {
            interfacesSelect.appendChild(createElement("option", {
                value: selectedInterface,
                selected: ""
            }, selectedInterface));
        }
    };

    async safeFetch(url, options) {
        showOverlay();
        try {
            const response = await fetch(url, options);
            return (await response.json())
        }
        catch (_) {
            return null;
        }
        finally {
            hideOverlay();
        }
    };

    async fetchInterfaces() {
        return (await this.safeFetch(`${this.API_BASE}/system/interfaces`)).interfaces.map(iface => iface.id);
    };

    markUnsaved(element) {
        element.classList.add("unsaved");
    }

    async fetchGroups() {
        const jsonData = await this.safeFetch(`${this.API_BASE}/groups?with_rules=true`);
        this.groupsElement.innerHTML = "";
        jsonData.groups.forEach(group => {
            const groupElement = createElement("div", {
                id: `group-${group.id}`,
                class: "group"
            }, ``+
                `<label for="group-${group.id}-name">Имя группы:</label><input id="group-${group.id}-name" value="${group.name}"><br/>`+
                `<label for="group-${group.id}-interface">Интерфейс:</label><select id="group-${group.id}-interface"></select><br/>`+
                `<label for="group-${group.id}-enable">Активировать группу</label><input id="group-${group.id}-enable" type="checkbox" ${group.enable ? "checked" : ""}><br/>`+
                `<button id="group-${group.id}-btnUpdateGroup">Сохранить</button><button id="group-${group.id}-btnDeleteGroup">Удалить</button><br/>`+
                `<h3>Правила</h3>`+
                `<div id="group-${group.id}-rules"></div>`+
                `<h3>Создать правило</h3>`+
                `<select id="group-${group.id}-ruleCreateType">`+
                    `<option value="namespace" selected>Namespace</option>`+
                    `<option value="wildcard">Wildcard</option>`+
                    `<option value="regex">Regex</option>`+
                    `<option value="domain">Domain</option>`+
                `</select>`+
                `<input id="group-${group.id}-ruleCreateName" placeholder="Имя правила">`+
                `<input id="group-${group.id}-ruleCreateRule" placeholder="Правило">`+
                `<input type="checkbox" id="group-${group.id}-ruleCreateEnable" checked>`+
                `<button id="group-${group.id}-btnCreateRule">Создать</button><br/>`+
            ``);
            this.populateInterfaces(groupElement.querySelector(`#group-${group.id}-interface`), this.interfaces, group.interface);
            groupElement.querySelector(`#group-${group.id}-name`).onchange = () => this.markUnsaved(groupElement);
            groupElement.querySelector(`#group-${group.id}-interface`).onchange = () => this.markUnsaved(groupElement);
            groupElement.querySelector(`#group-${group.id}-enable`).onchange = () => this.markUnsaved(groupElement);
            groupElement.querySelector(`#group-${group.id}-btnUpdateGroup`).onclick = () => this.updateGroup(group.id);
            groupElement.querySelector(`#group-${group.id}-btnDeleteGroup`).onclick = () => this.deleteGroup(group.id);
            groupElement.querySelector(`#group-${group.id}-btnCreateRule`).onclick = () => this.createRule(group.id);
            const rulesDiv = groupElement.querySelector(`#group-${group.id}-rules`);
            group.rules.forEach(rule => {
                const ruleElement = createElement("div", {
                    id: `group-${group.id}-rule-${rule.id}`,
                    class: "rule",
                }, ``+
                    `<select id="group-${group.id}-rule-${rule.id}-type">`+
                        `<option value="namespace" ${rule.type === "namespace" ? "selected" : ""}>Namespace</option>`+
                        `<option value="wildcard" ${rule.type === "wildcard" ? "selected" : ""}>Wildcard</option>`+
                        `<option value="regex" ${rule.type === "regex" ? "selected" : ""}>Regex</option>`+
                        `<option value="domain" ${rule.type === "domain" ? "selected" : ""}>Domain</option>`+
                    `</select>`+
                    `<input id="group-${group.id}-rule-${rule.id}-name" value="${rule.name}" placeholder="Имя правила">`+
                    `<input id="group-${group.id}-rule-${rule.id}-rule" value="${rule.rule}" placeholder="Правило">`+
                    `<input id="group-${group.id}-rule-${rule.id}-enable" type="checkbox" ${rule.enable ? "checked" : ""}>`+
                    `<button id="group-${group.id}-rule-${rule.id}-btnUpdateRule">Сохранить</button>`+
                    `<button id="group-${group.id}-rule-${rule.id}-btnDeleteRule">Удалить</button>`+
                ``);
                ruleElement.querySelector(`#group-${group.id}-rule-${rule.id}-type`).onchange = () => this.markUnsaved(ruleElement);
                ruleElement.querySelector(`#group-${group.id}-rule-${rule.id}-name`).onchange = () => this.markUnsaved(ruleElement);
                ruleElement.querySelector(`#group-${group.id}-rule-${rule.id}-rule`).onchange = () => this.markUnsaved(ruleElement);
                ruleElement.querySelector(`#group-${group.id}-rule-${rule.id}-enable`).onchange = () => this.markUnsaved(ruleElement);
                ruleElement.querySelector(`#group-${group.id}-rule-${rule.id}-btnUpdateRule`).onclick = () => this.updateRule(group.id, rule.id);
                ruleElement.querySelector(`#group-${group.id}-rule-${rule.id}-btnDeleteRule`).onclick = () => this.deleteRule(group.id, rule.id);
                rulesDiv.appendChild(ruleElement);
            });
            this.groupsElement.appendChild(groupElement);
        });
    };

    async createGroup() {
        await this.safeFetch(`${this.API_BASE}/groups`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                name: document.getElementById("groupCreateName").value,
                interface: document.getElementById("groupCreateInterface").value,
                enable: document.getElementById("groupCreateEnable").checked,
            })
        });
        await this.fetchGroups();
    };

    async updateGroup(groupId) {
        await this.safeFetch(`${this.API_BASE}/groups/${groupId}`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                name: document.getElementById(`group-${groupId}-name`).value,
                interface: document.getElementById(`group-${groupId}-interface`).value,
                enable: document.getElementById(`group-${groupId}-enable`).checked
            })
        });
        await this.fetchGroups();
    };

    async deleteGroup(groupId) {
        if (!confirm("Вы уверены, что хотите удалить группу?")) {
            return
        }
        await this.safeFetch(`${this.API_BASE}/groups/${groupId}`, {
            method: "DELETE"
        });
        await this.fetchGroups();
    };

    async createRule(groupId) {
        await this.safeFetch(`${this.API_BASE}/groups/${groupId}/rules`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                name: document.getElementById(`group-${groupId}-ruleCreateName`).value,
                rule: document.getElementById(`group-${groupId}-ruleCreateRule`).value,
                type: document.getElementById(`group-${groupId}-ruleCreateType`).value,
                enable: document.getElementById(`group-${groupId}-ruleCreateEnable`).checked,
            })
        });
        await this.fetchGroups();
    }

    async updateRule(groupId, ruleId) {
        await this.safeFetch(`${this.API_BASE}/groups/${groupId}/rules/${ruleId}`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                name: document.getElementById(`group-${groupId}-rule-${ruleId}-name`).value,
                rule: document.getElementById(`group-${groupId}-rule-${ruleId}-rule`).value,
                type: document.getElementById(`group-${groupId}-rule-${ruleId}-type`).value,
                enable: document.getElementById(`group-${groupId}-rule-${ruleId}-enable`).checked
            })
        });
        await this.fetchGroups();
    }

    async deleteRule(groupId, ruleId) {
        if (!confirm("Вы уверены, что хотите удалить правило?")) {
            return
        }
        await this.safeFetch(`${this.API_BASE}/groups/${groupId}/rules/${ruleId}`, {
            method: "DELETE"
        });
        await this.fetchGroups();
    }

    async saveConfig() {
        if (!confirm("Сохранить текущую конфигурацию? Это перезапишет файл!")) {
            return
        }
        await this.safeFetch(`${this.API_BASE}/system/config/save`, {
            method: "POST"
        });
        await this.fetchGroups();
    };
}
window.addEventListener("load", async () => {
    new App(document.querySelector("#app"));
});