import React from 'react';
import { render } from '@testing-library/react';
import { Dashboard } from '../Dashboard';
import { Blogs } from '../Blogs';
import { Categorias } from '../Categorias';
import { Clusters } from '../Clusters';
import { Prompts } from '../Prompts';
import { GeracaoArtigos } from '../GeracaoArtigos';
import { Feedback } from '../Feedback';
import { Exportacao } from '../Exportacao';
import { StatusLogs } from '../StatusLogs';
import { Tokens } from '../Tokens';
import { I18nextProvider } from 'react-i18next';
import { useI18n } from '../../hooks/use_i18n';

describe('Renderização de páginas principais com i18n', () => {
  it('renderiza todas as páginas em pt-BR', () => {
    const { t, setLang } = useI18n();
    setLang('pt_BR');
    expect(render(<Dashboard />)).toMatchSnapshot();
    expect(render(<Blogs />)).toMatchSnapshot();
    expect(render(<Categorias />)).toMatchSnapshot();
    expect(render(<Clusters />)).toMatchSnapshot();
    expect(render(<Prompts />)).toMatchSnapshot();
    expect(render(<GeracaoArtigos />)).toMatchSnapshot();
    expect(render(<Feedback />)).toMatchSnapshot();
    expect(render(<Exportacao />)).toMatchSnapshot();
    expect(render(<StatusLogs />)).toMatchSnapshot();
    expect(render(<Tokens />)).toMatchSnapshot();
  });
  it('renderiza todas as páginas em en-US', () => {
    const { t, setLang } = useI18n();
    setLang('en_US');
    expect(render(<Dashboard />)).toMatchSnapshot();
    expect(render(<Blogs />)).toMatchSnapshot();
    expect(render(<Categorias />)).toMatchSnapshot();
    expect(render(<Clusters />)).toMatchSnapshot();
    expect(render(<Prompts />)).toMatchSnapshot();
    expect(render(<GeracaoArtigos />)).toMatchSnapshot();
    expect(render(<Feedback />)).toMatchSnapshot();
    expect(render(<Exportacao />)).toMatchSnapshot();
    expect(render(<StatusLogs />)).toMatchSnapshot();
    expect(render(<Tokens />)).toMatchSnapshot();
  });
}); 