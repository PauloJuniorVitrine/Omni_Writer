/**
 * Índice dos Componentes de Layout - Omni Writer
 * 
 * Exportação centralizada de todos os componentes de layout
 * 
 * @author Claude Sonnet 3.7 Max
 * @date 2025-01-27
 * @tracing_id UI_IMPLEMENTATION_20250127_001
 */

// ===== COMPONENTES PRINCIPAIS =====
export { Header, SimpleHeader, HeaderWithNavigation, HeaderWithUser } from './Header';
export { Sidebar, CollapsedSidebar, OverlaySidebar, LeftSidebar, RightSidebar, NarrowSidebar, WideSidebar } from './Sidebar';
export { Footer, MinimalFooter, ExtendedFooter, OmniWriterFooter } from './Footer';
export { MainLayout, LayoutWithSidebar, LayoutWithoutSidebar, LayoutWithHeader, LayoutWithoutHeader, LayoutWithFooter, LayoutWithoutFooter, FullLayout, ContentOnlyLayout, OmniWriterLayout } from './MainLayout';
export { Branding } from './Branding';

// ===== EXPORTAÇÃO PADRÃO =====
// Exportações individuais disponíveis acima 