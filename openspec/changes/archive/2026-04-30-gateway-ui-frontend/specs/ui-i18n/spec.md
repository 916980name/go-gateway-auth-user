## ADDED Requirements

### Requirement: i18n infrastructure with react-i18next
The application SHALL use react-i18next for internationalization with JSON namespace files per feature domain.

#### Scenario: i18n initializes with default language
- **WHEN** the application loads
- **THEN** react-i18next SHALL initialize with the language from localStorage, falling back to `zh-CN` if not set

#### Scenario: Namespace files are organized by domain
- **WHEN** i18n is configured
- **THEN** translation files SHALL exist at `src/locales/{locale}/{namespace}.json` with namespaces: `common`, `menu`, `tenant`, `user`, `role`, `permission`

### Requirement: zh-CN locale
The application SHALL provide complete Chinese (Simplified) translations for all UI text.

#### Scenario: All UI text is translated to Chinese
- **WHEN** the language is set to zh-CN
- **THEN** all labels, buttons, messages, table headers, form fields, and error messages SHALL display in Chinese

### Requirement: en-US locale
The application SHALL provide complete English translations for all UI text.

#### Scenario: All UI text is translated to English
- **WHEN** the language is set to en-US
- **THEN** all labels, buttons, messages, table headers, form fields, and error messages SHALL display in English

### Requirement: Ant Design locale integration
The Ant Design ConfigProvider SHALL be configured with the matching locale for date pickers, pagination, table empty states, and other built-in components.

#### Scenario: Ant Design components use correct locale
- **WHEN** the language is set to zh-CN
- **THEN** Ant Design components (Table pagination, DatePicker, Empty state) SHALL display in Chinese

#### Scenario: Switching language updates Ant Design locale
- **WHEN** the user switches from zh-CN to en-US
- **THEN** Ant Design component text SHALL also switch to English
