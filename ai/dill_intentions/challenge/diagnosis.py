import pygame
import sys
from pathlib import Path
import dill
import numpy as np

MODEL_PATH = "model.dill"

pygame.init()

SCREEN_WIDTH = 800
SCREEN_HEIGHT = 600
FPS = 60

BG_COLOR = (15, 25, 40)
PANEL_COLOR = (30, 45, 70)
BUTTON_YES = (50, 150, 50)
BUTTON_NO = (180, 50, 50)
BUTTON_HOVER = (70, 170, 70)
TEXT_COLOR = (240, 240, 240)
ACCENT_COLOR = (100, 200, 255)

FONT_LARGE = pygame.font.Font(None, 48)
FONT_MEDIUM = pygame.font.Font(None, 32)
FONT_SMALL = pygame.font.Font(None, 24)


class Predictor:
    
    def __init__(self):
        self.model = None
        self.feature_names = []
        self.tree = None
        self.load_model()
        self.reset()
    
    def load_model(self):
        model_path = Path(MODEL_PATH)
        if not model_path.exists():
            print(f"Model file not found at {model_path}")
            return
        
        try:
            with open(model_path, 'rb') as f:
                data = dill.load(f)
            
            if isinstance(data, dict):
                self.model = data.get('model')
            else:
                self.model = data
            
            if self.model is not None:
                if hasattr(self.model, 'feature_names'):
                    self.feature_names = self.model.feature_names
                elif hasattr(self.model, 'feature_names_in_'):
                    self.feature_names = list(self.model.feature_names_in_)
                
                self.tree = self.model.tree_
                print(f"Model loaded!")
        except Exception as e:
            print(f"Error loading model: {e}")
            import traceback
            traceback.print_exc()
            self.model = None
    
    def reset(self):
        self.current_node = 0
        self.question_count = 0
        self.result = None
        self.game_over = False
        self.confidence = 1.0
    
    def get_current_question(self):
        if self.model is None:
            return "Model not loaded"
        
        if self.game_over:
            return None
        if self.tree.feature[self.current_node] == -2:
            return None
        
        feature_idx = self.tree.feature[self.current_node]
        if feature_idx < len(self.feature_names):
            return self.symptom_to_question(self.feature_names[feature_idx])
        return f"Question {feature_idx}?"
    
    def symptom_to_question(self, symptom_name):
        if symptom_name.endswith('?'):
            return symptom_name
        symptom = symptom_name.strip().replace('_', ' ').lower()
        return f"Do you have {symptom}?"
    
    def answer_question(self, answer):
        if self.model is None or self.game_over:
            return False
        
        self.question_count += 1
        
        if answer:
            self.current_node = self.tree.children_right[self.current_node]
        else:
            self.current_node = self.tree.children_left[self.current_node]
        
        if self.tree.feature[self.current_node] == -2:
            self.game_over = True
            self.finish_game()
            return True
        
        return False
    
    def finish_game(self):
        node_values = self.tree.value[self.current_node].flatten()
        class_idx = int(np.argmax(node_values))
        
        if hasattr(self.model, 'classes_') and class_idx < len(self.model.classes_):
            self.result = self.model.classes_[class_idx]
            self.confidence = 1.0
        else:
            self.result = "Prediction error"
            self.confidence = 0
    
    def get_result(self):
        return self.result


class Button:
    def __init__(self, x, y, width, height, text, color):
        self.rect = pygame.Rect(x, y, width, height)
        self.text = text
        self.color = color
        self.is_hovered = False
    
    def draw(self, surface):
        color = BUTTON_HOVER if self.is_hovered else self.color
        pygame.draw.rect(surface, color, self.rect, border_radius=8)
        pygame.draw.rect(surface, TEXT_COLOR, self.rect, 2, border_radius=8)
        
        text_surf = FONT_SMALL.render(self.text, True, TEXT_COLOR)
        text_rect = text_surf.get_rect(center=self.rect.center)
        surface.blit(text_surf, text_rect)
    
    def update(self, mouse_pos):
        self.is_hovered = self.rect.collidepoint(mouse_pos)
    
    def is_clicked(self, event):
        if event.type == pygame.MOUSEBUTTONDOWN and event.button == 1:
            return self.rect.collidepoint(event.pos)
        return False


def wrap_text(text, font, max_width):
    words = text.split(' ')
    lines = []
    current_line = []
    
    for word in words:
        word_width, _ = font.size(word)
        if word_width > max_width:
            chunk = ""
            for char in word:
                test_chunk = chunk + char
                chunk_width, _ = font.size(test_chunk)
                if chunk_width > max_width:
                    if current_line:
                        lines.append(' '.join(current_line))
                        current_line = []
                    if chunk:
                        lines.append(chunk)
                    chunk = char
                else:
                    chunk = test_chunk
            if chunk:
                current_line.append(chunk)
        else:
            current_line.append(word)
            width, _ = font.size(' '.join(current_line))
            if width > max_width:
                if len(current_line) == 1:
                    lines.append(current_line[0])
                    current_line = []
                else:
                    current_line.pop()
                    lines.append(' '.join(current_line))
                    current_line = [word]
    
    if current_line:
        lines.append(' '.join(current_line))
    
    return lines


class ClinicalDiagnosisGame:
    def __init__(self):
        self.screen = pygame.display.set_mode((SCREEN_WIDTH, SCREEN_HEIGHT))
        pygame.display.set_caption("Disease Diagnosis")
        self.clock = pygame.time.Clock()
        
        self.game = Predictor()
        self.state = "MENU"
        self.current_question = None
        
        btn_width = 150
        btn_height = 50
        btn_y = 450
        spacing = 20
        center_x = SCREEN_WIDTH // 2
        
        self.yes_button = Button(center_x - btn_width - spacing//2, btn_y, btn_width, btn_height, "YES", BUTTON_YES)
        self.no_button = Button(center_x + spacing//2, btn_y, btn_width, btn_height, "NO", BUTTON_NO)
        self.start_button = Button(center_x - 100, 350, 200, 60, "START", ACCENT_COLOR)
        self.restart_button = Button(center_x - 100, 450, 200, 50, "RESTART", ACCENT_COLOR)
    
    def draw_menu(self):
        self.screen.fill(BG_COLOR)
        
        title = FONT_LARGE.render("DIAGNOSIS SUPPORT", True, ACCENT_COLOR)
        title_rect = title.get_rect(center=(SCREEN_WIDTH//2, 150))
        self.screen.blit(title, title_rect)
        
        instructions = [
            "Answer the questions",
            "Get your diagnosis"
        ]
        y = 230
        for line in instructions:
            text = FONT_SMALL.render(line, True, TEXT_COLOR)
            text_rect = text.get_rect(center=(SCREEN_WIDTH//2, y))
            self.screen.blit(text, text_rect)
            y += 30
        
        self.start_button.draw(self.screen)
    
    def draw_playing(self):
        self.screen.fill(BG_COLOR)
        
        title = FONT_MEDIUM.render("DIAGNOSIS IN PROGRESS", True, ACCENT_COLOR)
        title_rect = title.get_rect(center=(SCREEN_WIDTH//2, 50))
        self.screen.blit(title, title_rect)
        
        progress_text = f"Question {self.game.question_count + 1}"
        progress_surf = FONT_SMALL.render(progress_text, True, TEXT_COLOR)
        self.screen.blit(progress_surf, (20, 20))
        
        panel_rect = pygame.Rect(50, 120, SCREEN_WIDTH - 100, 250)
        pygame.draw.rect(self.screen, PANEL_COLOR, panel_rect, border_radius=10)
        pygame.draw.rect(self.screen, ACCENT_COLOR, panel_rect, 2, border_radius=10)
        
        if self.current_question:
            lines = wrap_text(self.current_question, FONT_MEDIUM, panel_rect.width - 40)
            y = panel_rect.centery - (len(lines) * 20)
            for line in lines:
                text_surf = FONT_MEDIUM.render(line, True, TEXT_COLOR)
                text_rect = text_surf.get_rect(center=(SCREEN_WIDTH//2, y))
                self.screen.blit(text_surf, text_rect)
                y += 40
        
        self.yes_button.draw(self.screen)
        self.no_button.draw(self.screen)
    
    def draw_result(self):
        self.screen.fill(BG_COLOR)
        
        title = FONT_MEDIUM.render("DIAGNOSIS COMPLETE", True, ACCENT_COLOR)
        title_rect = title.get_rect(center=(SCREEN_WIDTH//2, 80))
        self.screen.blit(title, title_rect)
        
        panel_rect = pygame.Rect(50, 150, SCREEN_WIDTH - 100, 200)
        pygame.draw.rect(self.screen, PANEL_COLOR, panel_rect, border_radius=10)
        pygame.draw.rect(self.screen, ACCENT_COLOR, panel_rect, 2, border_radius=10)
        
        result = self.game.get_result() or "Unknown"
        lines = wrap_text(result, FONT_MEDIUM, panel_rect.width - 40)
        y = panel_rect.centery - (len(lines) * 20)
        for line in lines:
            text_surf = FONT_MEDIUM.render(line, True, TEXT_COLOR)
            text_rect = text_surf.get_rect(center=(SCREEN_WIDTH//2, y))
            self.screen.blit(text_surf, text_rect)
            y += 40
        
        conf_text = f"Confidence: {self.game.confidence:.0%}"
        conf_surf = FONT_SMALL.render(conf_text, True, TEXT_COLOR)
        conf_rect = conf_surf.get_rect(center=(SCREEN_WIDTH//2, panel_rect.bottom + 30))
        self.screen.blit(conf_surf, conf_rect)
        
        self.restart_button.draw(self.screen)
    
    def run(self):
        running = True
        while running:
            mouse_pos = pygame.mouse.get_pos()
            
            if self.state == "MENU":
                self.start_button.update(mouse_pos)
            elif self.state == "PLAYING":
                self.yes_button.update(mouse_pos)
                self.no_button.update(mouse_pos)
            elif self.state == "RESULT":
                self.restart_button.update(mouse_pos)
            
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    running = False
                elif event.type == pygame.KEYDOWN:
                    if event.key == pygame.K_ESCAPE:
                        running = False
                
                if self.state == "MENU":
                    if self.start_button.is_clicked(event):
                        self.game.reset()
                        self.current_question = self.game.get_current_question()
                        self.state = "PLAYING"
                
                elif self.state == "PLAYING":
                    if self.yes_button.is_clicked(event):
                        game_over = self.game.answer_question(True)
                        if game_over:
                            self.state = "RESULT"
                        else:
                            self.current_question = self.game.get_current_question()
                    
                    elif self.no_button.is_clicked(event):
                        game_over = self.game.answer_question(False)
                        if game_over:
                            self.state = "RESULT"
                        else:
                            self.current_question = self.game.get_current_question()
                
                elif self.state == "RESULT":
                    if self.restart_button.is_clicked(event):
                        self.state = "MENU"
            
            if self.state == "MENU":
                self.draw_menu()
            elif self.state == "PLAYING":
                self.draw_playing()
            elif self.state == "RESULT":
                self.draw_result()
            
            pygame.display.flip()
            self.clock.tick(FPS)
        
        pygame.quit()
        sys.exit()


if __name__ == "__main__":
    app = ClinicalDiagnosisGame()
    app.run()
